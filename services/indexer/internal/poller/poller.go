// Package poller implements the Sorolens indexer worker.
// It reads all tracked contracts from the store, fetches new events and
// invocations from the Soroban RPC, and persists them to Postgres.
//
// The poller never imports apps/api directly. It depends only on the
// RPCClient, Store, and RedisClient interfaces defined in interfaces.go so
// that tests can substitute fakes without touching the network or database.
package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/sorolens/sorolens/services/indexer/internal/anomaly"
	"github.com/sorolens/sorolens/services/indexer/internal/healthscore"
	"github.com/sorolens/sorolens/services/indexer/internal/metrics"
	"github.com/sorolens/sorolens/services/indexer/internal/partition"
	"github.com/sorolens/sorolens/services/indexer/internal/wasm"
)

const (
	// defaultNetworkLabel is the value used for the "network" metric label
	// when the poller is wired with the single unnamed RPC client (no
	// per-network SOROBAN_RPC_URL_* variables configured), issue #198.
	defaultNetworkLabel = "default"

	// maxEventRetries is how many times a single event is retried before
	// it is parked in the dead-letter queue (issue #202).
	maxEventRetries = 3

	// lockTTL is the Redis advisory lock lifetime per contract.
	// Set to twice the expected maximum per-contract processing time.
	lockTTL = 60 * time.Second

	// lockKeyPrefix is the Redis key prefix for per-contract indexer locks.
	lockKeyPrefix = "sorolens:lock:indexer:"

	// newContractBackfillWindow is how many ledgers back to start a backfill
	// for a contract with no prior sync state. At ~5s per ledger this is
	// approximately 6 days, safely within the 7-day RPC retention window.
	newContractBackfillWindow uint32 = 100_000
)

// Config holds runtime parameters for the Poller.
type Config struct {
	// LedgerWindow is the maximum number of ledgers to request per getEvents
	// call. Matches INDEXER_LEDGER_WINDOW from the API config.
	LedgerWindow uint32
	// PollInterval is the sleep duration between full passes in continuous mode.
	PollInterval time.Duration
	// MaxDuration is the wall-clock budget for a single once-mode pass.
	// If a pass exceeds this, the poller logs a warning and exits cleanly.
	MaxDuration time.Duration

	// AnomalyEnabled turns the per-pass anomaly detection job on (default off;
	// issue #136). Indexer main.go wires it via env.
	AnomalyEnabled bool
	// AnomalyLookbackHours is the rolling baseline window, default 168 (7 days).
	AnomalyLookbackHours int
	// AnomalySigma is the standard-deviation threshold, default 3.
	AnomalySigma float64
	// AnomalyMinHistory is the minimum samples before detection starts.
	AnomalyMinHistory int
}

// Poller fetches and persists events and invocations for all tracked contracts.
type Poller struct {
	rpcClients map[string]RPCClient
	store      Store
	redis      RedisClient
	cfg        Config
	log        *slog.Logger
	// metrics records the per-network lag gauges on every pass (issue #198).
	// It is nil unless SetMetrics is called; nil disables metric recording.
	metrics *metrics.Recorder
}

// SetMetrics attaches the Prometheus recorder the poller updates on every
// pass (issue #198). It must be called before Run; when it is never called
// metric recording is skipped, so existing callers are unaffected.
func (p *Poller) SetMetrics(r *metrics.Recorder) {
	p.metrics = r
}

// New returns a Poller wired with the given dependencies.
// It preserves the existing single-client behavior by using the provided RPC
// client for all contracts when no network-specific map is needed.
func New(rpc RPCClient, store Store, redis RedisClient, cfg Config, log *slog.Logger) *Poller {
	return NewWithRPCClients(map[string]RPCClient{"": rpc}, store, redis, cfg, log)
}

// NewWithRPCClients returns a Poller that routes each contract to the RPC
// client matching its network. Contracts with an unconfigured network are
// skipped with a warning.
func NewWithRPCClients(rpcClients map[string]RPCClient, store Store, redis RedisClient, cfg Config, log *slog.Logger) *Poller {
	return &Poller{rpcClients: rpcClients, store: store, redis: redis, cfg: cfg, log: log}
}

// Run starts the poller in the given mode.
// mode must be "once" or "continuous".
// The context controls graceful shutdown: when ctx is cancelled the poller
// finishes the current contract then returns.
func (p *Poller) Run(ctx context.Context, mode string) error {
	switch mode {
	case "once":
		return p.runOnce(ctx)
	case "continuous":
		return p.runContinuous(ctx)
	default:
		return fmt.Errorf("poller: unknown mode %q (want once|continuous)", mode)
	}
}

// runOnce executes one full pass and exits.
// If the pass takes longer than cfg.MaxDuration, it logs a warning and
// returns nil (clean exit for GitHub Actions cron runners).
func (p *Poller) runOnce(ctx context.Context) error {
	start := time.Now()
	if p.cfg.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.cfg.MaxDuration)
		defer cancel()
	}

	err := p.processAll(ctx)
	elapsed := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		p.log.Warn("indexer run exceeded max-duration, exiting cleanly",
			"elapsed", elapsed,
			"max_duration", p.cfg.MaxDuration,
		)
		return nil
	}
	return err
}

// runContinuous loops until ctx is cancelled, sleeping PollInterval between passes.
func (p *Poller) runContinuous(ctx context.Context) error {
	for {
		if err := p.processAll(ctx); err != nil {
			p.log.Error("indexer pass error", "err", err)
		}
		select {
		case <-ctx.Done():
			p.log.Info("indexer shutting down")
			return nil
		case <-time.After(p.cfg.PollInterval):
		}
	}
}

// processAll fetches and indexes events for every active contract.
func (p *Poller) processAll(ctx context.Context) error {
	// Ensure the next month's partition exists before processing.
	if err := partition.EnsureNextMonthPartition(ctx, p.store); err != nil {
		p.log.Warn("failed to ensure next month partition", "err", err)
	}

	var cursor string
	for {
		// Check for shutdown between contract batches.
		if ctx.Err() != nil {
			return nil
		}

		contracts, next, err := p.store.ListContracts(ctx, cursor, 50)
		if err != nil {
			return fmt.Errorf("list contracts: %w", err)
		}

		for _, c := range contracts {
			if ctx.Err() != nil {
				return nil
			}
			if c.Status != "active" && c.Status != "backfilling" {
				continue
			}
			// An in-flight batch must finish on a context detached from shutdown,
			// so a SIGTERM mid-fetch cannot tear the commit in half.
			if err := p.processContract(context.WithoutCancel(ctx), c); err != nil {
				// Log and continue; one failing contract must not block others.
				p.log.Error("failed to index contract",
					"contract_id", c.ID,
					"err", err,
				)
			}
		}

		if next == "" {
			break
		}
		cursor = next
	}

	// Record per-network lag after the contract batches have committed their
	// cursors so the gauge reflects the tip reached by this pass (issue #198).
	p.observeNetworkLag(ctx)

	if p.cfg.AnomalyEnabled {
		p.runAnomalyDetection(ctx)
	}
	p.runHealthScores(ctx)
	return nil
}

// alertTxKey builds the deterministic de-duplication key for an anomaly alert.
// The contract_alerts table de-duplicates on (tx_hash, contract_id), so this
// synthetic key prevents re-inserting the same alert on every 5-minute pass.
func alertTxKey(metric string, ref time.Time) string {
	return fmt.Sprintf("anomaly:%s:%s", metric, ref.UTC().Format("2006-01-02T15"))
}

// runAnomalyDetection is the periodic anomaly-detection job (issue #136).
// For every active contract it builds a rolling baseline of per-hour activity
// and inserts a Warning contract alert for each metric that spikes more than
// AnomalySigma standard deviations above its mean.
//
// The job is best-effort: store or detection errors are logged and never
// block the indexing pass. It respects context cancellation so the 5-minute
// cadence in continuous mode and once-mode shutdown both behave cleanly.
func (p *Poller) runAnomalyDetection(ctx context.Context) {
	start := time.Now()
	samplesByContract := make(map[string][]anomaly.Sample)

	var cursor string
	for {
		if ctx.Err() != nil {
			return
		}
		contracts, next, err := p.store.ListContracts(ctx, cursor, 50)
		if err != nil {
			p.log.Error("anomaly: list contracts", "err", err)
			return
		}
		for _, c := range contracts {
			if ctx.Err() != nil {
				return
			}
			if c.Status != "active" && c.Status != "backfilling" {
				continue
			}
			samples, err := p.hourlyActivity(ctx, c.ID)
			if err != nil {
				p.log.Warn("anomaly: fetch hourly activity",
					"contract_id", c.ID,
					"err", err,
				)
				continue
			}
			samplesByContract[c.ID] = samples
		}
		if next == "" {
			break
		}
		cursor = next
	}

	var detected int
	for contractID, samples := range samplesByContract {
		cfg := anomaly.Config{
			Sigma:      p.cfg.AnomalySigma,
			MinHistory: p.cfg.AnomalyMinHistory,
		}
		for _, a := range anomaly.Detect(samples, cfg) {
			alert := Alert{
				ContractID: contractID,
				Severity:   "Warning",
				Message:    a.Message,
				Ledger:     0,
				TxHash:     alertTxKey(a.Metric, a.At),
				Timestamp:  time.Now().UTC(),
			}
			if err := p.store.InsertAlert(ctx, alert); err != nil {
				p.log.Warn("anomaly: insert alert",
					"contract_id", contractID,
					"metric", a.Metric,
					"err", err,
				)
				continue
			}
			detected++
			p.log.Warn("anomaly detected",
				"contract_id", contractID,
				"metric", a.Metric,
				"observed", a.Observed,
				"threshold", a.Expected,
			)
		}
	}

	p.log.Info("anomaly detection pass complete",
		"contracts", len(samplesByContract),
		"alerts", detected,
		"duration", time.Since(start),
	)
}

// hourlyActivity fetches the rolling window of per-hour activity for a
// contract and converts it to the detector's sample format (oldest first).
func (p *Poller) hourlyActivity(ctx context.Context, contractID string) ([]anomaly.Sample, error) {
	lookback := p.cfg.AnomalyLookbackHours
	if lookback <= 0 {
		lookback = anomaly.DefaultLookbackHours
	}
	buckets, err := p.store.RecentHourlyActivity(ctx, contractID, lookback)
	if err != nil {
		return nil, err
	}
	samples := make([]anomaly.Sample, 0, len(buckets))
	for _, b := range buckets {
		samples = append(samples, anomaly.Sample{
			At:          b.Hour,
			Events:      float64(b.EventCount),
			Invocations: float64(b.InvokeCount),
			CPU:         float64(b.CPU),
			Fees:        float64(b.Fees),
		})
	}
	return samples, nil
}

// runHealthScores refreshes the cached composite health score (issue #137) for
// every active contract. The job is best-effort like the anomaly pass: store
// errors are logged and never block the indexing pass, and the score for a
// contract with no data yet still gets computed from zero-inputs so the cache
// table receives a row on the first poll.
func (p *Poller) runHealthScores(ctx context.Context) {
	start := time.Now()
	var scored int

	var cursor string
	for {
		if ctx.Err() != nil {
			return
		}
		contracts, next, err := p.store.ListContracts(ctx, cursor, 50)
		if err != nil {
			p.log.Error("health score: list contracts", "err", err)
			return
		}
		for _, c := range contracts {
			if ctx.Err() != nil {
				return
			}
			if c.Status != "active" && c.Status != "backfilling" {
				continue
			}
			inputs, err := p.store.ContractHealthInputs(ctx, c.ID)
			if err != nil {
				p.log.Warn("health score: fetch inputs",
					"contract_id", c.ID,
					"err", err,
				)
				continue
			}
			score := healthscore.Compute(healthInputsToScoreInputs(inputs))
			if err := p.store.UpsertContractHealthScore(ctx, ContractHealthScore{
				ContractID:           c.ID,
				Score:                score.Overall,
				ComponentUptime:      score.Uptime,
				ComponentErrorRate:   score.ErrorRate,
				ComponentPerformance: score.Performance,
				ComponentStorageTTL:  score.StorageTTL,
				ComputedAt:           time.Now().UTC(),
			}); err != nil {
				p.log.Warn("health score: upsert",
					"contract_id", c.ID,
					"err", err,
				)
				continue
			}
			scored++
			p.log.Debug("health score updated",
				"contract_id", c.ID,
				"score", score.Overall,
			)
		}
		if next == "" {
			break
		}
		cursor = next
	}

	p.log.Info("health score pass complete",
		"contracts_scored", scored,
		"duration", time.Since(start),
	)
}

// healthInputsToScoreInputs converts the poller's mirror HealthInputs into the
// pure healthscore package's Inputs type.
func healthInputsToScoreInputs(in HealthInputs) healthscore.Inputs {
	activity := make([]healthscore.Activity, 0, len(in.Activity))
	for _, a := range in.Activity {
		activity = append(activity, healthscore.Activity{
			Invocations: a.InvokeCount,
			CPU:         a.CPU,
			Fees:        a.Fees,
		})
	}
	return healthscore.Inputs{
		HealthyChecks:     in.HealthyChecks,
		TotalChecks:       in.TotalChecks,
		WatchdogStatus:    in.WatchdogStatus,
		TotalInvocations:  in.TotalInvocations,
		FailedInvocations: in.FailedInvocations,
		Activity:          activity,
		TotalStorage:      in.TotalStorage,
		ExpiringStorage:   in.ExpiringStorage,
	}
}

// processContract indexes all new events for one contract. It also checks the
// contract's on-chain Wasm hash for upgrades before scanning events so a code
// upgrade with no indexable events still gets recorded.
func (p *Poller) processContract(ctx context.Context, contract Contract) error {
	contractID := contract.ID
	network := contract.Network
	rpc, ok := p.selectRPCClient(network)
	if !ok {
		p.log.Warn("skipping contract with unconfigured network",
			"contract_id", contractID,
			"network", network,
		)
		return nil
	}

	// Acquire per-contract advisory lock to prevent concurrent runs.
	lockKey := lockKeyPrefix + contractID
	acquired, err := p.redis.SetNX(ctx, lockKey, "1", lockTTL)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	if !acquired {
		p.log.Info("contract locked by another runner, skipping",
			"contract_id", contractID)
		return nil
	}
	defer p.redis.Del(ctx, lockKey) //nolint:errcheck

	// Detect Wasm upgrades (contract code changes) before scanning events so
	// an upgrade with no indexable events still gets recorded. Any error here
	// must not block event indexing, so we log and continue.
	if err := p.checkWasmHash(ctx, rpc, contract); err != nil {
		p.log.Warn("wasm upgrade check failed (continuing)",
			"contract_id", contractID,
			"err", err,
		)
	}

	latest, err := rpc.GetLatestLedger(ctx)
	if err != nil {
		return fmt.Errorf("get latest ledger: %w", err)
	}

	syncState, err := p.store.GetSyncState(ctx, contractID)
	if err != nil {
		return fmt.Errorf("get sync state: %w", err)
	}

	networkCursor, err := p.store.GetIndexerCursor(ctx, network)
	if err != nil {
		p.log.Warn("failed to fetch indexer cursor for network (continuing)",
			"network", network,
			"err", err,
		)
	}

	var startLedger uint32
	if syncState.LastLedger == 0 {
		if networkCursor > 0 {
			// Resume after the last successfully committed network batch
			startLedger = networkCursor + 1
		} else if latest.Sequence > newContractBackfillWindow {
			// New contract: best-effort backfill from within the retention window.
			startLedger = latest.Sequence - newContractBackfillWindow
		} else {
			startLedger = 1
		}
		p.log.Warn("starting sync for contract",
			"contract_id", contractID,
			"start_ledger", startLedger,
			"network_cursor", networkCursor,
		)
	} else {
		startLedger = syncState.LastLedger + 1
	}

	if startLedger > latest.Sequence {
		p.log.Info("contract is up to date",
			"contract_id", contractID,
			"last_ledger", syncState.LastLedger,
		)
		return nil
	}

	// Fetch events in windows to respect RPC page limits.
	endLedger := min32(startLedger+p.cfg.LedgerWindow-1, latest.Sequence)

	log := p.log.With(
		"contract_id", contractID,
		"start_ledger", startLedger,
		"end_ledger", endLedger,
	)
	log.Info("indexing contract")

	runStart := time.Now()
	events, invocations, err := p.fetchWindow(ctx, rpc, contractID, network, startLedger, endLedger)
	if err != nil {
		return err
	}

	newState := SyncState{ContractID: contractID, LastLedger: endLedger}
	if err := p.store.BatchInsertWithCursor(ctx, network, endLedger, events, invocations, newState); err != nil {
		// A single poison event must not stall the contract. Fall back to
		// isolating the batch: retry each event on its own, park the ones
		// that keep failing in the dead-letter queue (issue #202), and then
		// commit the rest so the cursor still advances.
		if dlqErr := p.insertEventsWithDLQ(ctx, events); dlqErr != nil {
			return fmt.Errorf("insert events: %w", dlqErr)
		}
		if len(invocations) > 0 {
			if invErr := p.store.BatchInsertInvocations(ctx, invocations); invErr != nil {
				return fmt.Errorf("batch insert invocations: %w", invErr)
			}
		}
		if stateErr := p.store.UpsertSyncState(ctx, newState); stateErr != nil {
			return fmt.Errorf("upsert sync state: %w", stateErr)
		}
		if curErr := p.store.SetIndexerCursor(ctx, network, endLedger); curErr != nil {
			return fmt.Errorf("set indexer cursor: %w", curErr)
		}
	}

	// ---- Wasm hash transition detection (issue #276) ----------------------
	if wasmHash, hashErr := rpc.GetContractWasmHash(ctx, contractID); hashErr != nil {
		// Non-fatal: a single RPC miss must not stall the rest of the indexer.
		p.log.Warn("failed to fetch contract wasm hash, skipping version check",
			"contract_id", contractID,
			"err", hashErr,
		)
	} else if wasmHash != "" {
		p.maybeRecordVersion(ctx, contractID, wasmHash, endLedger, invocations)
	}

	log.Info("contract indexed",
		"events", len(events),
		"invocations", len(invocations),
		"duration", time.Since(runStart),
	)
	return nil
}

// insertEventsWithDLQ persists events one at a time, retrying each up to
// maxEventRetries times. An event that still cannot be stored is parked in the
// dead-letter queue (issue #202) and the remaining events are still processed,
// so a single bad event can no longer block a contract's indexing pass.
//
// Per-event rather than per-batch by design: BatchInsertEvents rejects the
// whole slice when any one element is bad, so retrying as a batch would park
// the good events alongside the bad one.
func (p *Poller) insertEventsWithDLQ(ctx context.Context, events []Event) error {
	type failed struct {
		ev  Event
		err error
	}
	wrote := 0
	var failures []failed

	for _, ev := range events {
		var lastErr error
		stored := false
		for attempt := 1; attempt <= maxEventRetries; attempt++ {
			if err := p.store.BatchInsertEvents(ctx, []Event{ev}); err != nil {
				lastErr = err
				continue
			}
			stored = true
			break
		}
		if stored {
			wrote++
			continue
		}
		failures = append(failures, failed{ev: ev, err: lastErr})
	}
	if len(failures) == 0 {
		return nil
	}

	// Parking is only meaningful when the store proved it can still take
	// writes. If not one event in the batch could be written, this is a
	// store-wide outage rather than a poison payload: surfacing an error keeps
	// the caller from advancing the cursor over data that was never persisted
	// and stops a connection blip from flooding the dead-letter queue.
	if wrote == 0 {
		return fmt.Errorf("store rejected every event in the batch: %w", failures[0].err)
	}

	for _, f := range failures {
		// EventPayload is what the requeue endpoint re-inserts, so it must be a
		// JSON-serialized Event: handler/dlq.go unmarshals it back into
		// store.Event. Event holds only plain fields, so a marshal failure is
		// unreachable in practice — park the row anyway rather than drop it.
		payload, marshalErr := json.Marshal(f.ev)
		msg := "insert retries exhausted"
		switch {
		case marshalErr != nil:
			p.log.Error("marshal event for DLQ", "event_id", f.ev.ID, "err", marshalErr)
			payload, msg = nil, "marshal payload: "+marshalErr.Error()
		case f.err != nil:
			msg = f.err.Error()
		}

		if err := p.store.InsertFailedEvent(ctx, FailedEvent{
			EventID:      f.ev.ID,
			ContractID:   f.ev.ContractID,
			Network:      f.ev.Network,
			EventPayload: payload,
			ErrorMessage: msg,
			Attempts:     maxEventRetries,
		}); err != nil {
			// The event is now stored nowhere, which the caller must know about.
			return fmt.Errorf("park event %s in DLQ: %w", f.ev.ID, err)
		}
		p.log.Warn("event parked in DLQ",
			"event_id", f.ev.ID,
			"contract_id", f.ev.ContractID,
			"attempts", maxEventRetries,
			"err", msg,
		)
	}
	return nil
}

// checkWasmHash compares the current on-chain Wasm hash of the contract's
// instance entry against the hash observed on the previous poll. A mismatch
// means the contract code was upgraded. The change is recorded as a
// ContractUpgrade row and the stored hash is refreshed so later polls diff
// against the new value.
//
// Best-effort by design: a transient RPC error or an unreadable entry is
// reported to the caller, and processContract logs it without failing the
// event index pass.
func (p *Poller) checkWasmHash(ctx context.Context, rpc RPCClient, contract Contract) error {
	key, err := wasm.ContractInstanceKey(contract.ID)
	if err != nil {
		return fmt.Errorf("build instance key: %w", err)
	}

	res, err := rpc.GetLedgerEntries(ctx, []string{key})
	if err != nil {
		return fmt.Errorf("get instance entry: %w", err)
	}

	var currentHash string
	for _, e := range res.Entries {
		if h, ok := wasm.WasmHashFromInstanceEntry(e.XDR); ok {
			currentHash = h
			break
		}
	}
	if currentHash == "" {
		// Entry not yet readable (e.g. ledger retention); nothing to record.
		return nil
	}

	// First observed hash: baseline it without recording an upgrade.
	if contract.WasmHash == "" {
		if err := p.store.UpdateContractWasmHash(ctx, contract.ID, currentHash); err != nil {
			return fmt.Errorf("baseline contract wasm hash: %w", err)
		}
		if err := p.cacheWasmBinary(ctx, rpc, currentHash); err != nil {
			p.log.Warn("wasm binary cache failed (continuing)",
				"contract_id", contract.ID,
				"wasm_hash", currentHash,
				"err", err,
			)
		}
		return nil
	}

	if currentHash == contract.WasmHash {
		// Hash unchanged — still ensure the binary is cached (e.g. after
		// deploying the Wasm-cache feature against already-tracked contracts).
		if err := p.cacheWasmBinary(ctx, rpc, currentHash); err != nil {
			p.log.Warn("wasm binary cache failed (continuing)",
				"contract_id", contract.ID,
				"wasm_hash", currentHash,
				"err", err,
			)
		}
		return nil // unchanged
	}

	upgrade := ContractUpgrade{
		ContractID: contract.ID,
		FromHash:   contract.WasmHash,
		ToHash:     currentHash,
		Ledger:     ledgerFromEntry(res),
		At:         time.Now().UTC(),
	}
	if err := p.store.InsertContractUpgrade(ctx, upgrade); err != nil {
		return fmt.Errorf("insert contract upgrade: %w", err)
	}
	if err := p.store.UpdateContractWasmHash(ctx, contract.ID, currentHash); err != nil {
		return fmt.Errorf("update contract wasm hash: %w", err)
	}
	if err := p.cacheWasmBinary(ctx, rpc, currentHash); err != nil {
		p.log.Warn("wasm binary cache failed after upgrade (continuing)",
			"contract_id", contract.ID,
			"wasm_hash", currentHash,
			"err", err,
		)
	}

	p.log.Info("contract code upgraded",
		"contract_id", contract.ID,
		"from_hash", contract.WasmHash,
		"to_hash", currentHash,
	)
	return nil
}

// observeNetworkLag records the per-network indexer lag (issue #198), defined
// as the network head ledger minus the last ledger committed for that network
// (its indexer cursor). It runs once per pass for every configured network, so
// both the currently active and merely cached networks report a value rather
// than a single hard-coded one.
//
// Best-effort by design: a transient RPC or store error for one network is
// logged and skipped without failing the indexing pass.
func (p *Poller) observeNetworkLag(ctx context.Context) {
	if p.metrics == nil {
		return
	}

	networks := make([]string, 0, len(p.rpcClients))
	for network := range p.rpcClients {
		networks = append(networks, network)
	}
	sort.Strings(networks)

	for _, network := range networks {
		if ctx.Err() != nil {
			return
		}
		rpc := p.rpcClients[network]
		if rpc == nil {
			continue
		}

		label := network
		if label == "" {
			label = defaultNetworkLabel
		}

		head, err := rpc.GetLatestLedger(ctx)
		if err != nil {
			p.log.Warn("metrics: latest ledger unavailable",
				"network", label,
				"err", err,
			)
			continue
		}
		if head == nil {
			continue
		}

		cursor, err := p.store.GetIndexerCursor(ctx, network)
		if err != nil {
			p.log.Warn("metrics: indexer cursor unavailable",
				"network", label,
				"err", err,
			)
			continue
		}

		p.metrics.ObserveNetwork(label, head.Sequence, cursor)
	}
}

func (p *Poller) maybeRecordVersion(
	ctx context.Context,
	contractID, wasmHash string,
	endLedger uint32,
	invocations []Invocation,
) {
	prev, err := p.store.GetLatestContractVersion(ctx, contractID)
	if err != nil && err != ErrVersionNotFound {
		p.log.Warn("failed to get latest contract version",
			"contract_id", contractID, "err", err)
		return
	}

	// No change: the current hash matches the most recently recorded one.
	if err == nil && prev.WasmHash == wasmHash {
		return
	}

	cv := ContractVersion{
		ContractID:      contractID,
		WasmHash:        wasmHash,
		FirstSeenLedger: int64(endLedger),
		TxHash:          anchorTxHash(invocations),
	}
	if recordErr := p.store.RecordContractVersion(ctx, cv); recordErr != nil {
		p.log.Warn("failed to record contract version",
			"contract_id", contractID,
			"wasm_hash", wasmHash,
			"err", recordErr,
		)
		return
	}
	p.log.Info("new wasm hash detected, version recorded",
		"contract_id", contractID,
		"wasm_hash", wasmHash,
		"first_seen_ledger", endLedger,
	)
}

func anchorTxHash(invocations []Invocation) string {
	var best Invocation
	for _, inv := range invocations {
		if inv.Ledger > best.Ledger {
			best = inv
		}
	}
	return best.TxHash
}

// cacheWasmBinary fetches the CONTRACT_CODE ledger entry for wasmHash and
// stores the raw bytes in the content-addressed Wasm cache (issue #162).
// Best-effort: missing entries and decode failures are non-fatal so event
// indexing is never blocked by a Wasm fetch problem.
func (p *Poller) cacheWasmBinary(ctx context.Context, rpc RPCClient, wasmHash string) error {
	exists, err := p.store.HasContractWasm(ctx, wasmHash)
	if err != nil {
		return fmt.Errorf("has contract wasm: %w", err)
	}
	if exists {
		return nil
	}

	key, err := wasm.ContractCodeKey(wasmHash)
	if err != nil {
		return fmt.Errorf("build code key: %w", err)
	}
	res, err := rpc.GetLedgerEntries(ctx, []string{key})
	if err != nil {
		return fmt.Errorf("get code entry: %w", err)
	}
	var code []byte
	for _, e := range res.Entries {
		if c, ok := wasm.WasmCodeFromEntry(e.XDR); ok {
			code = c
			break
		}
	}
	if len(code) == 0 {
		// Code entry not yet readable (retention / race); retry next poll.
		return nil
	}
	if err := p.store.UpsertContractWasm(ctx, wasmHash, code); err != nil {
		return fmt.Errorf("upsert contract wasm: %w", err)
	}
	p.log.Info("cached contract wasm binary",
		"wasm_hash", wasmHash,
		"size_bytes", len(code),
	)
	return nil
}

// ledgerFromEntry returns the modification ledger of the first instance entry
// if present, falling back to the latest ledger reported by the RPC result.
func ledgerFromEntry(res *GetLedgerEntriesResult) uint32 {
	for _, e := range res.Entries {
		if e.LastModifiedLedgerSeq != 0 {
			return e.LastModifiedLedgerSeq
		}
	}
	if res.LatestLedger != 0 {
		return res.LatestLedger
	}
	return 0
}

// fetchWindow calls getEvents for [startLedger, endLedger] and fetches the
// corresponding transactions for each unique tx hash. The contract's network
// is stamped onto every row so multi-network queries can filter on it.
func (p *Poller) fetchWindow(ctx context.Context, rpc RPCClient, contractID, network string, startLedger, endLedger uint32) ([]Event, []Invocation, error) {
	filters := []EventFilter{{
		Type:        "contract",
		ContractIDs: []string{contractID},
	}}

	result, err := rpc.GetEvents(ctx, startLedger, endLedger, filters)
	if err != nil {
		return nil, nil, fmt.Errorf("get events [%d,%d]: %w", startLedger, endLedger, err)
	}

	var events []Event
	seenTx := make(map[string]struct{})

	for _, re := range result.Events {
		closedAt, _ := time.Parse(time.RFC3339, re.LedgerClosedAt)
		events = append(events, Event{
			ID:               re.ID,
			ContractID:       re.ContractID,
			Network:          network,
			Ledger:           re.Ledger,
			LedgerClosedAt:   closedAt,
			TxHash:           re.TxHash,
			Type:             re.Type,
			TopicXDR:         re.Topic,
			ValueXDR:         re.Value,
			InSuccessfulCall: re.InSuccessfulContractCall,
		})
		seenTx[re.TxHash] = struct{}{}
	}

	// Fetch one transaction record per unique tx hash.
	var invocations []Invocation
	for txHash := range seenTx {
		tx, err := rpc.GetTransaction(ctx, txHash)
		if err != nil {
			p.log.Warn("failed to fetch transaction, skipping",
				"tx_hash", txHash,
				"err", err,
			)
			continue
		}
		invocations = append(invocations, Invocation{
			TxHash:           txHash,
			ContractID:       contractID,
			Network:          network,
			Ledger:           tx.Ledger,
			LedgerClosedAt:   tx.LedgerClosedAt,
			Status:           tx.Status,
			ResultXDR:        tx.ResultXDR,
			ApplicationOrder: tx.ApplicationOrder,
		})
	}

	return events, invocations, nil
}

func (p *Poller) selectRPCClient(network string) (RPCClient, bool) {
	if p.rpcClients == nil {
		return nil, false
	}
	if network == "" {
		if rpc, ok := p.rpcClients[""]; ok {
			return rpc, true
		}
		if len(p.rpcClients) == 1 {
			for _, rpc := range p.rpcClients {
				return rpc, true
			}
		}
		return nil, false
	}
	rpc, ok := p.rpcClients[network]
	return rpc, ok
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
