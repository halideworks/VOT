//! One serving connection: replay memory and outbound accounting.

use super::{
    Error, ErrorKind, Fault, Payload, RECORD_LANE, Session, TransportAdapter, VecDeque, error_code,
    is_backpressure,
};
use vot_transport_api::PathStats;

/// Outbound budget. Bounds the queue against a peer pipelining faster than it drains.
pub(crate) const OUTBOUND_BUDGET_BYTES: u64 = 2 * vot_scheduler::MAX_PROOF_RANGE_BYTES;

/// Request identities remembered for replay detection. An exact duplicate is
/// re-answered; a duplicate identifier with different content is a protocol error.
pub(crate) const REMEMBERED_REQUESTS: usize = 64;

/// Packets in one loss decision. Smaller observations are accumulated so
/// service-loop cadence cannot turn a handful of drops into a path verdict.
const FEC_SAMPLE_PACKETS: u64 = 8192;

/// Packets in the first decision only. A transfer a few seconds long is
/// mostly issued before a full sample closes, so the first verdict comes
/// from a cover's worth of packets and the steady cadence takes over from
/// there (ADR-0042). Closing early on a detected loss instead was
/// measured seeding the smoothed rate at a fraction of the truth,
/// because detection trails sending by about a round trip and the close
/// divides a fresh loss count by every packet the seeded flight already
/// sent; one such run never engaged at all.
const FIRST_FEC_SAMPLE_PACKETS: u64 = 256;

/// Generations whose fate is known in one decode sample.
///
/// Counted as they resolve rather than as they are coded, so both halves
/// of the ratio come off the same stream of reports. An outcome reaches
/// this end well after the generation was coded, by `GEN_DONE` or by the
/// epoch's quiet retirement, and counting the coding instead put the two
/// halves on different clocks: whichever way the mismatch was resolved it
/// misjudged the sample that spans a change of verdict, once by charging
/// an old attempt's failures to a fresh denominator and once by closing a
/// sample before any of its own outcomes had arrived.
///
/// Small, because the whole cost of this verdict is how long it takes to
/// reach: outcomes arrive in lumps at epoch retirement, and the smoothing
/// below is what absorbs the noise a short sample carries. Measured on the
/// 4 GiB shaped cell, 128 gave 63.07 s and 48 gives 61.42 against 68.22
/// unjudged and 56.10 with coding off, and the genuinely lossy cell is
/// unmoved between them.
pub(crate) const FEC_DECODE_SAMPLE: u64 = 48;

/// The share of coded generations that may fail before coding is judged
/// to be making the path worse: a quarter, of the smoothed rate.
///
/// Measured, this separates the two cases with room on both sides. A path
/// whose loss is exogenous decodes every coded generation it engages for,
/// 100% across every emulated cell and a real 12 GiB transfer at 5% loss.
/// A path whose loss is the sender's own queue overflowing decoded 39-40%
/// of coded, because the repair symbols queue behind the sources they
/// were sent to repair.
///
/// Read against the smoothed rate rather than one sample, for the reason
/// the loss verdict is: failures do not arrive spread out. A generation
/// that never gathers enough symbols owes no `GEN_DONE`, so its epoch's
/// quiet retirement reports the whole epoch at once, and a sample sees
/// either none of that or half of it. Measured on a genuinely lossy
/// 4 GiB transfer whose overall failure rate was 1.9%, nine of 359 raw
/// samples crossed a quarter on their own, and acting on them cost that
/// arm coding it should have kept.
const DECODE_FAILURE_SHARE: u64 = 4;

/// Closed loss windows the first decode failure holds coding off for.
///
/// Coding cannot be judged while it is off, because a generation that is
/// never coded never reports, so the off-hysteresis on the loss rate
/// cannot be what governs re-entry: the loss that engaged coding is still
/// there, and the verdict would flap engage, fail, disengage, re-engage
/// for the length of the transfer. A counted hold bounds that duty cycle
/// instead, and the first one is short so a path that has genuinely
/// changed is retried rather than written off on one bad sample.
const DECODE_FAILURE_HOLD_WINDOWS: u32 = 4;

/// Doublings the hold may take across repeated failures on one
/// connection.
///
/// A fixed hold is not enough on its own, because this end learns a
/// generation's fate well after it coded it: the receiver owes no
/// `GEN_DONE` for a generation that never gathered enough symbols to
/// decode, so the whole truth arrives at the epoch's quiet retirement. A
/// path that keeps failing therefore pays a fresh sample plus that lag
/// for every retry, and a fixed hold buys one retry per hold for the
/// length of the transfer. Doubling bounds the retries a connection can
/// spend in total, and at the cap the hold outlasts any transfer, so a
/// path that has failed five samples is left alone.
const DECODE_FAILURE_BACKOFF_CAP: u32 = 4;

#[derive(Clone, Copy, Debug)]
struct PathCounters {
    lost: u64,
    spurious: u64,
    sent: u64,
}

/// Recent path loss, activation hysteresis, and the repair count it supports.
#[derive(Debug)]
pub(crate) struct FecPolicy {
    previous: Option<PathCounters>,
    sample_lost: u64,
    sample_sent: u64,
    coding: bool,
    repair_symbols: usize,
    /// Whether a sample has closed yet; the first closes early (ADR-0042).
    decided: bool,
    /// Smoothed loss rate in [`RATE_ONE`]ths, an exponential average over
    /// the closed windows. The verdict reads this rather than one window:
    /// loss detection bunches real drops into some windows and starves
    /// others, and per-window hysteresis was measured flapping a steadily
    /// lossy path off half the time.
    smoothed_loss: u64,
    /// Generations resolved toward the current decode decision, and how
    /// many of them the receiver could not decode from symbols.
    resolved_sample: u64,
    failed_sample: u64,
    /// The share of coded generations failing, in [`RATE_ONE`]ths,
    /// smoothed across samples the way the loss rate is.
    smoothed_failure: u64,
    /// How many times that share has been zeroed. A verdict deferred
    /// under one value describes the sample that ended, so it is dropped
    /// rather than folded onto the fresh one.
    failure_base: u64,
    /// Loss windows still owed to a decode failure before coding may be
    /// reconsidered, and how many samples have failed on this connection,
    /// which is what lengthens the next hold.
    hold: u32,
    decode_failures: u32,
    /// The last unaided window rates, where the next one goes, and their
    /// mean: the path's own rate, measured only when this end is adding
    /// nothing to it.
    recent: [u32; PROBE_WINDOWS],
    recent_at: usize,
    recent_len: usize,
    unaided_loss: u64,
    /// The pause cadence: coded windows since the last pause, how many
    /// to allow before the next, and how many windows of the current
    /// pause remain.
    coded_since_probe: u32,
    probe_interval: u32,
    pausing: u32,
    /// When a pause with an RTT sample may begin measuring. Samples before
    /// this instant can still contain reports from the coded flight.
    probe_settle_until: Option<std::time::Instant>,
    /// Closed windows so far, only to skip the opening ramp.
    windows_closed: u32,
    /// Whether the last look said this path does not need coding.
    quiet_path: bool,
}

impl Default for FecPolicy {
    fn default() -> Self {
        Self {
            previous: None,
            sample_lost: 0,
            sample_sent: 0,
            coding: false,
            repair_symbols: super::server::FEC_REPAIR_SYMBOLS,
            decided: false,
            smoothed_loss: 0,
            resolved_sample: 0,
            failed_sample: 0,
            smoothed_failure: 0,
            failure_base: 0,
            hold: 0,
            decode_failures: 0,
            recent: [0; PROBE_WINDOWS],
            recent_at: 0,
            recent_len: 0,
            unaided_loss: 0,
            coded_since_probe: 0,
            probe_interval: PROBE_FIRST_INTERVAL,
            pausing: 0,
            probe_settle_until: None,
            windows_closed: 0,
            quiet_path: false,
        }
    }
}

/// The fixed-point unit the smoothed loss rate is held in. Wide enough
/// that the engagement edge is exact at the sample sizes the windows
/// close at: at 1/1024 a five-percent verdict over 8192 packets sat
/// between representable values.
const RATE_ONE: u64 = 65_536;

/// The smoothing weight's denominator: each closed window moves the
/// average a quarter of the way to its own rate. Four steady windows
/// carry most of a change through, so a real shift in the path lands in
/// about half a second of full-rate sending, while a single starved or
/// bunched window moves the verdict by at most a quarter of its error.
const RATE_SMOOTHING: u64 = 4;

/// The most a first lossy window may seed the smoothed rate with: a
/// quarter, well past the engagement rate.
///
/// It has to clear that rate with room, not sit on it. At `RATE_ONE / 10`
/// the ceiling is 6,553 units and `6553 * 10` is 65,530, one unit under
/// [`RATE_ONE`], so a seeded first window would fail the engagement test
/// by that unit and ADR-0042's first-sample decision would never fire on
/// a path at or above the bar.
pub(crate) const SEED_CEILING: u64 = RATE_ONE / 4;

/// Unaided windows the path's own rate is averaged over.
///
/// A trailing window rather than a mean over the connection, because a
/// mean that never forgets is carried over the bar by the ramp it opened
/// with: traced on a real 12 GiB transfer with coding off throughout,
/// the running mean climbs to 4.11% at windows seventeen through
/// twenty-one before decaying to 2.4% by window forty.
const PROBE_WINDOWS: usize = 16;

/// Unaided windows that must be in hand before a look will judge.
///
/// A pause always records this many windows after its settling prefix, so
/// this is a statement about the pause being long enough to mean anything
/// rather than a runtime gate that can fail.
const PROBE_MIN_WINDOWS: usize = 4;

/// Coded windows before the first pause, doubling to
/// [`PROBE_MAX_INTERVAL`] each time the pause says to carry on.
///
/// Every observable this end can read while coding runs is downstream of
/// coding's own traffic: loss, delay, drops, decode outcomes, and
/// whether decoding needed repair are all endogenous to the engagement
/// they would judge, which is why five in-band discriminators died the
/// same death on real paths. The only measurement that means anything is
/// one taken with nothing added to the path, so the policy stops adding
/// for a moment and looks. That is what a delay-targeting rate
/// controller does continuously and is the reason it never traps itself.
pub(crate) const PROBE_FIRST_INTERVAL: u32 = 8;

/// The longest a settled answer goes unchecked.
const PROBE_MAX_INTERVAL: u32 = 64;

/// Opening pause windows allowed for the coded flight to resolve when the
/// carrier has no RTT sample.
///
/// At the measured 218 ms WAN RTT, one loss window closes in about 80 ms;
/// reading those first windows attributed the coded flight's losses to the
/// unaided path and over-sized every later generation.
const PROBE_SETTLE_WINDOWS: u32 = 3;

/// Whole unaided windows recorded after the coded flight has settled.
const PROBE_MEASURE_WINDOWS: u32 = 4;

/// Fallback windows one pause lasts, including the settling prefix.
///
/// With RTT telemetry the wall clock replaces the opening three windows;
/// either path then records four whole unaided windows before judging.
const PROBE_PAUSE_WINDOWS: u32 = PROBE_SETTLE_WINDOWS + PROBE_MEASURE_WINDOWS;

/// The rate a look must read under for the path to be judged not to need
/// coding: the engagement rate, so the question is whether this path
/// would engage on its own merits when measured with nothing added.
pub(crate) const PROBE_BAR: u64 = RATE_ONE / 10;

/// Whether a measured rate is under the bar. Pure, so both sides of the
/// edge are pinned by a table test rather than by whichever cell happens
/// to straddle it.
pub(crate) const fn under_probe_bar(rate: u64) -> bool {
    rate < PROBE_BAR
}

/// Whether a smoothed rate earns coding on a path that is not coding:
/// 10.00%, a shade under the measured crossover where coding starts
/// paying for itself.
///
/// Pure for the same reason [`under_probe_bar`] is: the edge is one unit
/// wide and belongs in a table test rather than in whichever rig cell
/// happens to straddle it.
pub(crate) const fn engages(rate: u64) -> bool {
    rate * 10 >= RATE_ONE
}

/// Whether a smoothed rate keeps coding on a path already coding: 6.25%,
/// the off-hysteresis, five eighths of the engagement rate as it has
/// always been.
pub(crate) const fn stays_engaged(rate: u64) -> bool {
    rate * 16 >= RATE_ONE
}

impl FecPolicy {
    /// Adds the packets since the preceding carrier sample. Counter resets
    /// start a new baseline; missing telemetry leaves the last decision intact.
    pub(crate) fn observe(&mut self, stats: Option<PathStats>) {
        let Some(PathStats {
            smoothed_rtt_us,
            lost_packets: Some(lost),
            spurious_lost_packets: Some(spurious),
            packets_sent: Some(sent),
            ..
        }) = stats
        else {
            return;
        };
        let counters = PathCounters {
            lost,
            spurious,
            sent,
        };
        let Some(previous) = self.previous.replace(counters) else {
            return;
        };
        let (Some(lost), Some(spurious), Some(sent)) = (
            counters.lost.checked_sub(previous.lost),
            counters.spurious.checked_sub(previous.spurious),
            counters.sent.checked_sub(previous.sent),
        ) else {
            // A counter reset is a new baseline: what the old counters'
            // windows smoothed into the rate describes a path this one no
            // longer is.
            self.sample_lost = 0;
            self.sample_sent = 0;
            self.smoothed_loss = 0;
            self.resolved_sample = 0;
            self.failed_sample = 0;
            self.zero_failure();
            self.recent = [0; PROBE_WINDOWS];
            self.recent_at = 0;
            self.recent_len = 0;
            self.unaided_loss = 0;
            self.coded_since_probe = 0;
            self.probe_interval = PROBE_FIRST_INTERVAL;
            self.pausing = 0;
            self.probe_settle_until = None;
            self.windows_closed = 0;
            self.quiet_path = false;
            return;
        };
        if let Some(until) = self.probe_settle_until {
            // Keep advancing the counter baseline while the coded flight
            // drains. The first observation past the RTT becomes the clean
            // baseline, so the next whole packet window is unaided.
            self.sample_lost = 0;
            self.sample_sent = 0;
            if std::time::Instant::now() >= until {
                self.probe_settle_until = None;
            }
            return;
        }
        self.sample_lost = self
            .sample_lost
            .saturating_add(lost.saturating_sub(spurious));
        self.sample_sent = self.sample_sent.saturating_add(sent);
        let threshold = if self.decided {
            FEC_SAMPLE_PACKETS
        } else {
            FIRST_FEC_SAMPLE_PACKETS
        };
        if self.sample_sent < threshold {
            return;
        }
        self.decided = true;

        // The window's own rate folds into the smoothed one, and every
        // verdict below reads the smoothed rate: engagement at 10%, the
        // off-hysteresis at 6.25%, and the repair count, so one bunched or
        // starved window cannot flip what a steady path deserves.
        let window_rate = (self.sample_lost.saturating_mul(RATE_ONE)) / self.sample_sent.max(1);
        // Seeded whole by the first lossy window: until then there is
        // nothing to smooth, and quartering the first real observation
        // would hold engagement back three windows for no information.
        self.smoothed_loss = if self.smoothed_loss == 0 {
            // Capped: a genuinely lossy path still engages on its first
            // sample, but the raw rate of one freak 256-packet startup
            // burst was reviewed locking an otherwise clean path into
            // coding for up to thirteen windows of decay; from the
            // ceiling it is back under the off-hysteresis within five.
            window_rate.min(SEED_CEILING)
        } else {
            self.smoothed_loss - self.smoothed_loss / RATE_SMOOTHING + window_rate / RATE_SMOOTHING
        };
        let was_pausing = self.pausing > 0;
        self.observe_unaided(window_rate);
        self.run_probe(smoothed_rtt_us);
        // Engagement sits a shade under the measured crossover, the loss
        // rate where coding first pays for itself, rather than under the
        // loss rates it serves: below the crossover coding is slower than
        // the reliable path however well it decodes. Erring low is
        // deliberate, because the two errors cost differently
        // (ADR-0044's 2026-08-25 amendment).
        let engaged = if let Some(remaining) = self.hold.checked_sub(1) {
            // A decode failure is serving out its hold. The loss that
            // engaged coding is still on the path and would re-engage it
            // every window, so nothing about the loss rate is consulted
            // until the hold is spent.
            self.hold = remaining;
            false
        } else if self.coding {
            stays_engaged(self.smoothed_loss)
        } else {
            engages(self.smoothed_loss)
        };
        // A pause is a measurement, and the last one has the final word
        // on whether this path wants coding at all.
        let engaged = engaged && self.pausing == 0 && !self.quiet_path;
        if engaged && !self.coding {
            if !was_pausing {
                // A new engagement sizes from the loss that caused it, not
                // unaided history from an older, cleaner path state.
                self.recent_at = 0;
                self.recent_len = 0;
                self.unaided_loss = 0;
            }
            // An engagement is judged on its own outcomes. What is still
            // resolving from the last one arrives for generations coded
            // before it ended, and describes a path this may no longer be.
            // The smoothed rate goes with them: it only ever decays a
            // quarter a sample and it is above the bar by construction at
            // a disengage, so carrying it would spend the retry's first
            // clean sample crossing the bar again, however well the
            // retried path decodes. What bounds the retries is the hold
            // and its doubling, not this.
            self.resolved_sample = 0;
            self.failed_sample = 0;
            self.zero_failure();
        }
        // Once the path has been measured without redundancy in flight,
        // size redundancy from that measurement. Loss observed while coding
        // includes the repair traffic itself and otherwise makes coding buy
        // more coding. The smoothed rate remains the startup fallback.
        let measured_loss = if self.recent_len >= PROBE_MIN_WINDOWS {
            self.unaided_loss
        } else {
            self.smoothed_loss
        };
        let rate = u128::from(measured_loss);
        // Three times the expected losses across a generation's symbols,
        // plus one: at that margin a generation losing past its repair is
        // rarer than one in ten thousand at the loss rates this engages
        // for, so covered bytes stop paying retransmission round trips
        // (ADR-0042). The floor of two keeps one unlucky drop from
        // touching the reliable path on a barely lossy sample.
        self.repair_symbols = usize::try_from(
            (rate * 3 * vot_fec::MAX_SYMBOLS as u128).div_ceil(u128::from(RATE_ONE)) + 1,
        )
        .unwrap_or(super::server::FEC_REPAIR_SYMBOLS)
        .clamp(2, super::server::FEC_REPAIR_SYMBOLS);
        self.coding = engaged;
        self.sample_lost = 0;
        self.sample_sent = 0;
    }

    /// Takes a closed window into the unaided rate, if this end was
    /// adding nothing to the path while it ran.
    ///
    /// The opening window is the amplification-shaped ramp and describes
    /// no path, and a coded window describes coding as much as the path,
    /// so neither is evidence.
    fn observe_unaided(&mut self, window_rate: u64) {
        if self.coding || self.windows_closed == 0 || self.pausing > PROBE_MEASURE_WINDOWS {
            self.windows_closed = self.windows_closed.saturating_add(1);
            return;
        }
        self.windows_closed = self.windows_closed.saturating_add(1);
        self.recent[self.recent_at] = u32::try_from(window_rate).unwrap_or(u32::MAX);
        self.recent_at = (self.recent_at + 1) % PROBE_WINDOWS;
        self.recent_len = self.recent_len.saturating_add(1).min(PROBE_WINDOWS);
        let total: u64 = self.recent[..self.recent_len]
            .iter()
            .map(|rate| u64::from(*rate))
            .sum();
        self.unaided_loss = total / self.recent_len as u64;
    }

    /// Runs the pause cadence: counts coded windows toward the next
    /// look, spends a pause, and reads the verdict when one ends.
    fn run_probe(&mut self, smoothed_rtt_us: Option<u64>) {
        if self.pausing > 0 {
            self.pausing -= 1;
            if self.pausing == 0 {
                // One look decides, because the two errors are not the
                // same size. A look that wrongly says quiet corrects
                // itself within a few windows, since coding stops and
                // the unaided evidence then arrives every window. A look
                // that wrongly says carry on costs the 30% this exists
                // to remove, and on a path whose engagement flaps it may
                // be the last look for a long time, because the count
                // toward the next one only advances while coding.
                self.quiet_path = self.judged_quiet();
                if !self.quiet_path {
                    // A settled answer is not worth re-asking at the
                    // same rate, so the next look is further off.
                    self.probe_interval = self
                        .probe_interval
                        .saturating_mul(2)
                        .min(PROBE_MAX_INTERVAL);
                }
            }
            return;
        }
        if self.quiet_path {
            // Nothing is being added, so the evidence keeps arriving on
            // its own and a path that turns lossy is served again
            // without a pause to discover it.
            if self.recent_len >= PROBE_MIN_WINDOWS && !under_probe_bar(self.unaided_loss) {
                self.quiet_path = false;
                self.coded_since_probe = 0;
                self.probe_interval = PROBE_FIRST_INTERVAL;
            }
            return;
        }
        if !self.coding {
            return;
        }
        self.coded_since_probe = self.coded_since_probe.saturating_add(1);
        if self.coded_since_probe >= self.probe_interval {
            self.coded_since_probe = 0;
            self.probe_settle_until = smoothed_rtt_us.and_then(|rtt_us| {
                std::time::Instant::now().checked_add(std::time::Duration::from_micros(rtt_us))
            });
            self.pausing = if self.probe_settle_until.is_some() {
                PROBE_MEASURE_WINDOWS
            } else {
                PROBE_PAUSE_WINDOWS
            };
            // The look is over this pause's own windows and nothing
            // older, so the verdict cannot be carried by history from
            // before the engagement it is judging.
            self.recent_at = 0;
            self.recent_len = 0;
            self.unaided_loss = 0;
        }
    }

    /// Whether the unaided look says this path does not need coding.
    /// The bar is the engagement rate, not the disengagement rate below
    /// it: the question a look asks is whether this path would engage
    /// coding on its own merits, measured with nothing added. Both edges
    /// sit there rather than straddling, because a gap between them would
    /// let a path engage once on a burst and then be ratified forever by
    /// looks reading against a lower bar.
    const fn judged_quiet(&self) -> bool {
        self.recent_len >= PROBE_MIN_WINDOWS && under_probe_bar(self.unaided_loss)
    }

    /// Zeroes the failure share and moves the base with it, which is the
    /// only way it is ever zeroed: a verdict deferred under the old base
    /// has to be dropped rather than counted, because one retired epoch's
    /// unheard generations are a whole [`FEC_DECODE_SAMPLE`] of failures
    /// and folded onto a zeroed share they meet the quarter bar on
    /// equality. The rollover in `note_resolved` is not one of these: it
    /// closes a sample into the share rather than discarding the share,
    /// and the verdicts outstanding across it are the same engagement's.
    fn zero_failure(&mut self) {
        self.smoothed_failure = 0;
        self.failure_base = self.failure_base.saturating_add(1);
    }

    /// Which zeroing of the failure share the outcomes counted now belong
    /// to.
    pub(crate) const fn failure_base(&self) -> u64 {
        self.failure_base
    }

    /// Counts a coded generation the receiver decoded from symbols.
    pub(crate) fn note_decoded(&mut self) {
        self.note_resolved(false);
    }

    /// Counts a coded generation the receiver could not decode from
    /// symbols, which this end is repairing reliably instead.
    pub(crate) fn note_repaired(&mut self) {
        self.note_resolved(true);
    }

    /// Takes one generation's outcome, and judges the sample once it is
    /// full.
    ///
    /// Loss the sender caused itself is loss coding cannot answer: the
    /// repair symbols are more packets into the same overflowing queue, so
    /// they drop with the sources they were sent to repair and the coded
    /// arm pays its overhead for generations that decode anyway. Measured
    /// against a shaped bottleneck with no injected loss, the automatic
    /// policy engaged on every run, put 41% more packets into the queue
    /// (20,658 drops against 14,667), decoded 40% of what it coded, and
    /// cost 6.3% of the wall at 256 MB and 14% at 4 GiB. Nothing the
    /// sender can see about the path separates that from a lossy link:
    /// delay does not move (RTT sat within 1.3% of its minimum in the
    /// shaped cell, inside the range the clean and lossy cells both
    /// occupy) and neither does the normalized loss-event count. What
    /// separates them is whether the coding works, so that is what this
    /// reads.
    fn note_resolved(&mut self, failed: bool) {
        self.resolved_sample = self.resolved_sample.saturating_add(1);
        if failed {
            self.failed_sample = self.failed_sample.saturating_add(1);
        }
        if self.resolved_sample < FEC_DECODE_SAMPLE {
            return;
        }
        let sample_rate =
            (self.failed_sample.saturating_mul(RATE_ONE)) / self.resolved_sample.max(1);
        self.resolved_sample = 0;
        self.failed_sample = 0;
        // A sample that resolves while coding is off is the previous
        // attempt's tail arriving, and it is not weighed at all: it is the
        // evidence that ended that attempt, and an epoch's quiet
        // retirement reports every generation still under it at once, so
        // the tail is whole samples of near-total failure by construction.
        // Folded, it would end the next engagement on the last one's
        // record, however well the retried path decodes.
        if !self.coding {
            return;
        }
        self.smoothed_failure = self.smoothed_failure - self.smoothed_failure / RATE_SMOOTHING
            + sample_rate / RATE_SMOOTHING;
        if self.smoothed_failure.saturating_mul(DECODE_FAILURE_SHARE) < RATE_ONE {
            return;
        }
        self.coding = false;
        self.hold = DECODE_FAILURE_HOLD_WINDOWS
            .saturating_mul(1 << self.decode_failures.min(DECODE_FAILURE_BACKOFF_CAP));
        self.decode_failures = self.decode_failures.saturating_add(1);
    }

    pub(crate) const fn coding(&self) -> bool {
        self.coding
    }

    /// Whether the last unaided look said this path does not need
    /// coding.
    #[cfg(test)]
    pub(crate) const fn quiet_path(&self) -> bool {
        self.quiet_path
    }

    /// The path's own rate in [`RATE_ONE`]ths, from unaided windows.
    #[cfg(test)]
    pub(crate) const fn unaided_loss(&self) -> u64 {
        self.unaided_loss
    }

    /// The decode sample so far as `(resolved, failed)`.
    #[cfg(test)]
    pub(crate) const fn decode_sample(&self) -> (u64, u64) {
        (self.resolved_sample, self.failed_sample)
    }

    #[cfg(test)]
    pub(crate) const fn probe_state(&self) -> (u32, usize, u32, u32) {
        (
            self.pausing,
            self.recent_len,
            self.coded_since_probe,
            self.probe_interval,
        )
    }

    pub(crate) const fn repair_symbols(&self) -> usize {
        self.repair_symbols
    }
}

/// Per-session serving state, fresh for every accepted carrier.
pub struct ServeConnection {
    pub(crate) announced: bool,
    pub(crate) replay: ReplayWindow,
    pub(crate) outbound: OutboundQueue,
    /// Owed manifest pages as `(next, end)`. Paced rather than queued at once;
    /// a request may name thousands of pages.
    pub(crate) manifest_cursor: Option<(u64, u64)>,
    pub(crate) budget: u64,
    pub(crate) closed: Option<u16>,
    /// Answers queued this session, only ever increasing.
    pub(crate) progress: u64,
    /// Answers the carrier has taken, which the outbound budget may hide.
    pub(crate) handed_over: u64,
    /// Requests read while answers are backpressured. Kept in wire order so
    /// carrier-state events behind them can still be drained.
    pub(crate) deferred: VecDeque<Payload>,
    /// The datagram FEC sending state: what the peer's credit lets this end
    /// open and send. Used only while `fec_negotiated`.
    pub(crate) fec: FecSender,
    /// Whether the session negotiated both `DATAGRAM_FEC` and
    /// `FEC_COVER_EPOCHS`, refreshed each pass. The second declares a
    /// receiver that joins an epoch's generations to bundles by offset,
    /// which the cover-sized epochs this serve opens require, so a peer
    /// offering only the first is answered reliably.
    pub(crate) fec_negotiated: bool,
    /// Whether this path currently justifies coding new range answers.
    pub(crate) fec_coding: bool,
    /// Recent carrier loss and the FEC decision derived from it.
    pub(crate) fec_policy: FecPolicy,
    /// Per-epoch silence budget, derived from the path's smoothed round trip
    /// each service pass; the fixed default until the carrier reports one.
    pub(crate) quiet_grace: std::time::Duration,
}

impl Default for ServeConnection {
    fn default() -> Self {
        Self {
            announced: false,
            replay: ReplayWindow::default(),
            outbound: OutboundQueue::default(),
            manifest_cursor: None,
            budget: OUTBOUND_BUDGET_BYTES,
            closed: None,
            progress: 0,
            handed_over: 0,
            deferred: VecDeque::new(),
            fec: FecSender::default(),
            fec_negotiated: false,
            fec_coding: true,
            fec_policy: FecPolicy::default(),
            quiet_grace: super::server::EPOCH_QUIET_GRACE,
        }
    }
}

/// One epoch this serve opened across one requested cover: what to re-send
/// reliably when the receiver reports a generation abandoned or the epoch
/// refused.
#[derive(Clone, Debug)]
pub(crate) struct OpenedEpoch {
    pub(crate) root: [u8; 32],
    /// The piece bundles the epoch's generations belong to, ascending:
    /// each piece's first generation and its bundle identifier. A
    /// generation's record rides under the last piece at or before it,
    /// indexed relative to that piece.
    pub(crate) pieces: Vec<(u32, [u8; 16])>,
    /// Repair symbols the first pass transmitted per generation. The
    /// geometry declares the spec's whole repair count, so the ESIs past
    /// this are the reserve a symbol repair draws from (ADR-0042).
    pub(crate) transmitted_repairs: usize,
    /// Whether this epoch already spent its one symbol-repair rung. The
    /// second quiet deadline falls through to the reliable resend.
    pub(crate) symbol_repaired: bool,
    /// Generations already answered a targeted repair for, once each.
    pub(crate) repaired: std::collections::BTreeSet<u32>,
    /// The outbound mark this epoch's own symbol passes sit behind: the
    /// first pass, and the ladder's reserve rung. Written only by those,
    /// never by a targeted repair, so one repair's queued bytes cannot
    /// gate the sibling states that arrive in the same dispatch pass out
    /// of theirs.
    pub(crate) symbols_queued_through: u64,
    pub(crate) plan: vot_fec::EpochPlan,
    /// Generations still owed an outcome; the epoch closes when empty.
    pub(crate) live: std::collections::BTreeSet<u32>,
    /// The outbound mark this epoch's symbols sit behind. The carrier has
    /// taken all of them once it has taken this many bytes, which is what
    /// makes silence about the epoch mean the receiver is not answering
    /// rather than that this end has not handed them over yet.
    pub(crate) queued_through: u64,
    /// When this epoch's silence budget runs out, fixed from the grace in
    /// force when it was first seen with its symbols all on the carrier and
    /// nothing heard about it. Cleared by anything the receiver says about
    /// it, so it measures one epoch's own silence, and a later change in the
    /// path's grace never shortens a budget already partly spent.
    pub(crate) quiet_until: Option<std::time::Instant>,
}

impl OpenedEpoch {
    /// Repair ESIs the first pass held back for a symbol repair.
    pub(crate) fn reserve_repairs(&self) -> usize {
        self.plan
            .geometry()
            .repair_count()
            .saturating_sub(self.transmitted_repairs)
    }
}

/// Retired epochs whose verdict may wait for the receiver's word at once.
/// The queue drains on the grace, so this only bounds a burst of
/// retirements inside one of them.
pub(crate) const MAX_DEFERRED_EPOCHS: usize = 64;

/// The sender side of datagram FEC for one connection.
#[derive(Debug, Default)]
pub(crate) struct FecSender {
    pub(crate) sender: vot_fec::Sender,
    pub(crate) epochs: std::collections::BTreeMap<u32, OpenedEpoch>,
    /// Retired epochs the policy has not judged yet: when the wait for the
    /// receiver's word is up, the epoch, and the generations no word has
    /// come for. Drained from the front, which a shrinking grace can leave
    /// out of order; the effect is a later verdict for one entry and never
    /// an earlier one, because the front's own deadline still gates it.
    ///
    /// A quiet retirement is a timeout on the receiver's silence, not its
    /// word about decoding, and the two are far apart on a lossy path: the
    /// receiver owes a `GEN_DONE` for every generation it settled, and that
    /// frame queues behind the reliable traffic and the loss under it.
    /// Measured on a 12 GiB emulated transfer at 7% loss each way, 4,740
    /// generations were retired and 3,964 of them reported `Decoded`
    /// afterwards, 96.7% of those inside one more grace and all of them
    /// inside a second, against 392 the receiver truly could not decode.
    /// Judged at the retirement they are a twelve-fold over-count, and they
    /// arrive in whole epochs, so one retirement is a whole
    /// [`FEC_DECODE_SAMPLE`] of nothing but failures.
    pub(crate) pending_verdicts:
        VecDeque<(std::time::Instant, u32, std::collections::BTreeSet<u32>)>,
    /// The failure base the queued verdicts were deferred under.
    verdicts_base: u64,
}

impl FecSender {
    /// Drops every queued verdict when the policy has zeroed its failure
    /// share under them. They were deferred to be judged against the
    /// sample that has just been discarded, so they belong to it, and one
    /// retirement's worth of them lands on the fresh share as a whole
    /// sample of failures. Nothing counts them on the way out: the
    /// generations they name were resent when the epoch retired, and the
    /// share they would have voted on no longer exists. Nothing valid is
    /// lost either way: a fresh engagement is the only zeroing a running
    /// connection reaches, and the hold it waits out is four windows,
    /// which is under the grace on any path fast enough to close them.
    fn align(&mut self, base: u64) {
        if self.verdicts_base != base {
            self.verdicts_base = base;
            self.pending_verdicts.clear();
        }
    }

    /// Holds one retired epoch's unheard generations until `due`, and
    /// returns how many generations an overflow eviction gave up on.
    pub(crate) fn defer(
        &mut self,
        base: u64,
        due: std::time::Instant,
        epoch: u32,
        unheard: std::collections::BTreeSet<u32>,
    ) -> usize {
        self.align(base);
        self.pending_verdicts.push_back((due, epoch, unheard));
        // One in, at most one out: a branch rather than a drain, so no
        // arrangement of the two can loop.
        if self.pending_verdicts.len() > MAX_DEFERRED_EPOCHS {
            self.pending_verdicts
                .pop_front()
                .map_or(0, |(_, _, held)| held.len())
        } else {
            0
        }
    }

    /// Takes the receiver's late word about one generation, and says
    /// whether a deferred verdict was waiting for it. A repeat is not: the
    /// first word is the outcome and it is counted where it lands.
    pub(crate) fn settle(&mut self, base: u64, epoch: u32, generation: u32) -> bool {
        self.align(base);
        self.pending_verdicts
            .iter_mut()
            .find(|(_, held, _)| *held == epoch)
            .is_some_and(|(_, _, unheard)| unheard.remove(&generation))
    }

    /// Generations no word ever came for, once their wait is up.
    pub(crate) fn overdue(&mut self, base: u64, now: std::time::Instant) -> usize {
        self.align(base);
        let mut unheard = 0;
        while self
            .pending_verdicts
            .front()
            .is_some_and(|(due, _, _)| now >= *due)
        {
            unheard += self
                .pending_verdicts
                .pop_front()
                .map_or(0, |(_, _, held)| held.len());
        }
        unheard
    }
}

pub(crate) struct Remembered {
    pub(crate) frame_type: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) digest: [u8; 32],
}

pub(crate) enum Outbound {
    Control(Payload),
    Record(Payload),
    /// One FEC symbol datagram, in the same queue so the outbound budget and
    /// the backlog see it.
    Datagram(Payload),
}

impl Outbound {
    /// The answer's bytes, whichever lane carries it.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Control(frame) => frame.len(),
            Self::Record(record) => record.len(),
            Self::Datagram(symbol) => symbol.len(),
        }
    }

    /// Hands the answer to its lane: control frames as control, records
    /// shared on the record lane, symbols to the datagram path.
    pub(crate) fn send<A: TransportAdapter>(
        &self,
        session: &mut Session<A>,
    ) -> Result<(), vot_session::Error> {
        match self {
            Self::Control(frame) => session.send_control_shared(frame.clone()),
            Self::Record(record) => session.send_reliable_shared(RECORD_LANE, record.clone()),
            Self::Datagram(symbol) => session.send_datagram(0, symbol),
        }
    }
}

/// The queued answers and the bytes they hold, kept exactly together.
#[derive(Default)]
pub(crate) struct OutboundQueue {
    queue: VecDeque<Outbound>,
    bytes: u64,
    /// Bytes the carrier has taken over this connection's life, only ever
    /// going up. What is queued behind a given answer is `taken` at the
    /// moment it was queued plus [`Self::bytes`], so a caller can say when
    /// that answer has left this end without holding the answer itself.
    taken: u64,
}

impl OutboundQueue {
    pub(crate) fn push(&mut self, outbound: Outbound) {
        self.bytes = self.bytes.saturating_add(outbound.len() as u64);
        self.queue.push_back(outbound);
        debug_assert_eq!(
            self.bytes,
            self.queue.iter().map(|held| held.len() as u64).sum::<u64>(),
            "outbound bytes drifted from the queue"
        );
    }

    pub(crate) fn front(&self) -> Option<&Outbound> {
        self.queue.front()
    }

    /// Retires the front answer once the carrier took it.
    pub(crate) fn pop_sent(&mut self) {
        if let Some(sent) = self.queue.pop_front() {
            self.bytes = self.bytes.saturating_sub(sent.len() as u64);
            self.taken = self.taken.saturating_add(sent.len() as u64);
        }
        debug_assert_eq!(
            self.bytes,
            self.queue.iter().map(|held| held.len() as u64).sum::<u64>(),
            "outbound bytes drifted from the queue"
        );
    }

    /// Answer bytes queued and not yet taken.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Bytes the carrier has taken over this connection's life.
    pub(crate) fn taken(&self) -> u64 {
        self.taken
    }

    /// The mark an answer queued now would sit behind: everything already
    /// taken plus everything still waiting.
    pub(crate) fn queued_through(&self) -> u64 {
        self.taken.saturating_add(self.bytes)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Answers still queued.
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Request identities this session remembers, FIFO at a fixed bound.
#[derive(Default)]
pub(crate) struct ReplayWindow {
    remembered: VecDeque<Remembered>,
}

impl ReplayWindow {
    /// Admits a request as new or an exact replay, which is re-answered.
    /// The same identity over different bytes is the replay that is refused.
    pub(crate) fn admit(
        &mut self,
        frame_type: u64,
        request_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<(), Fault> {
        let digest = *blake3::hash(bytes).as_bytes();
        if let Some(seen) = self
            .remembered
            .iter()
            .find(|seen| seen.frame_type == frame_type && seen.request_id == request_id)
        {
            if seen.digest == digest {
                // Rebuild reproduces it: the bundle identity derives from the request bytes.
                return Ok(());
            }
            return Err(Fault::Peer(error_code::REPLAY_REJECTED));
        }
        if self.remembered.len() == REMEMBERED_REQUESTS {
            self.remembered.pop_front();
        }
        self.remembered.push_back(Remembered {
            frame_type,
            request_id,
            digest,
        });
        Ok(())
    }
}

impl ServeConnection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer bytes queued but not yet accepted by the carrier.
    #[must_use]
    pub fn pending_answer_bytes(&self) -> u64 {
        self.outbound.bytes()
    }

    /// Whether answers are still owed: queued frames, deferred requests, or
    /// unpaged manifest pages.
    #[must_use]
    pub fn has_backlog(&self) -> bool {
        !self.outbound.is_empty() || self.manifest_cursor.is_some() || !self.deferred.is_empty()
    }

    /// Records the close and drops pending answers.
    pub(crate) fn close_with(&mut self, code: u16) {
        self.closed = Some(code);
        self.outbound = OutboundQueue::default();
        self.manifest_cursor = None;
        self.deferred.clear();
    }

    /// Admits a request as new or an exact replay, which is re-answered.
    pub(crate) fn admit_request(
        &mut self,
        frame_type: u64,
        request_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<(), Fault> {
        self.replay.admit(frame_type, request_id, bytes)
    }

    /// Queued plus handed-over answers, only ever increasing. Both are needed:
    /// the outbound budget can stall queuing while the carrier still drains,
    /// or vice versa.
    ///
    /// This is what the session prepared, not what the wire carried: once
    /// the last answer is handed over both halves freeze however much of it
    /// the carrier still has to deliver. The stall budget adds the carrier's
    /// own counters to this for that reason.
    #[must_use]
    pub fn progress(&self) -> u64 {
        self.progress.saturating_add(self.handed_over)
    }

    /// One booked answer, whichever lane: progress and bytes move together.
    fn queue(&mut self, outbound: Outbound) {
        self.progress = self.progress.saturating_add(1);
        self.outbound.push(outbound);
    }

    pub(crate) fn queue_control(&mut self, frame: Payload) {
        self.queue(Outbound::Control(frame));
    }

    pub(crate) fn queue_record(&mut self, record: Payload) {
        self.queue(Outbound::Record(record));
    }

    pub(crate) fn queue_datagram(&mut self, symbol: Payload) {
        self.queue(Outbound::Datagram(symbol));
    }

    /// Hands queued answers to the session until the carrier refuses one.
    pub(crate) fn drain<A: TransportAdapter>(
        &mut self,
        session: &mut Session<A>,
    ) -> Result<(), Error> {
        while let Some(outbound) = self.outbound.front() {
            match outbound.send(session) {
                Ok(()) => {
                    // The loop's progress depends on the front leaving here:
                    // were it kept, a taken answer would be sent forever.
                    let held = self.outbound.len();
                    self.outbound.pop_sent();
                    debug_assert_eq!(
                        self.outbound.len(),
                        held - 1,
                        "a sent answer must leave the queue"
                    );
                    // Progress even under a stalled budget.
                    self.handed_over = self.handed_over.saturating_add(1);
                }
                // Backpressure: retry next pass.
                Err(error) if is_backpressure(&error) => break,
                Err(error) if matches!(error.kind(), ErrorKind::FrameExceedsLimit { .. }) => {
                    // Peer limits too small for this server's answers.
                    let _ = session.driver().close(error_code::FRAME_TOO_LARGE);
                    self.close_with(error_code::FRAME_TOO_LARGE);
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
