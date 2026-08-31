//! Rate limiting for pre-handshake audit records
//! (`03-supervisor.md` §8).
//!
//! `IdentityRejected` and pre-handshake `ProtocolViolation` records are
//! written **at most once per peer PID per 10-second window**; suppressed
//! events increment a counter that is folded into the detail of the next
//! written record. This is an audit-log DoS mitigation: a flood of
//! rejected connections (each would otherwise persist a chained record)
//! must not be able to grow the log unboundedly.
//!
//! The clock is injected so the window is testable without sleeping.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// The rejection window: one written record per PID per 10 seconds.
pub const WINDOW: Duration = Duration::from_secs(10);

/// Injectable clock, in whole seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// The real clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// The outcome of recording a rejection event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Write the record now. `suppressed` is the count of earlier events in
    /// this window that were not written; include it in the record's detail.
    Write { suppressed: u64 },
    /// Do not write; the event is counted toward the next written record.
    Suppress,
}

/// Per-PID rejection rate limiter.
///
/// Not a security boundary (it only paces audit writes); correctness here
/// degrades gracefully — a miss simply means one extra (or one fewer) record.
pub struct RejectionLimiter {
    inner: Mutex<HashMap<i32, Entry>>,
    clock: Box<dyn Clock>,
}

#[derive(Debug)]
struct Entry {
    last_write_secs: u64,
    suppressed: u64,
}

impl RejectionLimiter {
    /// Create a limiter with the system clock.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            clock: Box::new(SystemClock),
        }
    }

    /// Create a limiter with an injected clock (tests).
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Record a rejection event from `pid` and return the decision.
    pub fn record(&self, pid: i32) -> Decision {
        let mut map = self.inner.lock().unwrap();
        let now = self.clock.now_secs();
        match map.get_mut(&pid) {
            Some(e) if now.saturating_sub(e.last_write_secs) >= WINDOW.as_secs() => {
                let suppressed = e.suppressed;
                e.last_write_secs = now;
                e.suppressed = 0;
                Decision::Write { suppressed }
            }
            Some(e) => {
                e.suppressed = e.suppressed.saturating_add(1);
                Decision::Suppress
            }
            None => {
                map.insert(pid, Entry { last_write_secs: now, suppressed: 0 });
                Decision::Write { suppressed: 0 }
            }
        }
    }

    /// Drop all state (used on shutdown; also bounds memory under a flood of
    /// distinct PIDs — the map is only ever as large as the number of
    /// concurrent peers, which the connection cap already bounds).
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

impl Default for RejectionLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A clock the tests advance by hand. Clones share the same counter.
    #[derive(Default, Clone)]
    struct FakeClock(std::sync::Arc<AtomicU64>);

    impl Clock for FakeClock {
        fn now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn limiter() -> (RejectionLimiter, FakeClock) {
        let clock = FakeClock::default();
        let l = RejectionLimiter::with_clock(Box::new(clock.clone()));
        (l, clock)
    }

    #[test]
    fn first_event_writes() {
        let (l, _) = limiter();
        assert_eq!(l.record(100), Decision::Write { suppressed: 0 });
    }

    #[test]
    fn events_within_the_window_are_suppressed_then_counted() {
        let (l, clock) = limiter();
        assert_eq!(l.record(100), Decision::Write { suppressed: 0 });
        assert_eq!(l.record(100), Decision::Suppress);
        clock.0.store(5, Ordering::SeqCst);
        assert_eq!(l.record(100), Decision::Suppress);
        clock.0.store(9, Ordering::SeqCst);
        assert_eq!(l.record(100), Decision::Suppress);
        // 10s after the first write: write again, carrying the count.
        clock.0.store(10, Ordering::SeqCst);
        assert_eq!(l.record(100), Decision::Write { suppressed: 3 });
    }

    #[test]
    fn distinct_pids_are_independent() {
        let (l, _) = limiter();
        assert_eq!(l.record(1), Decision::Write { suppressed: 0 });
        assert_eq!(l.record(2), Decision::Write { suppressed: 0 });
        assert_eq!(l.record(1), Decision::Suppress);
        assert_eq!(l.record(2), Decision::Suppress);
    }

    #[test]
    fn suppression_accumulates_under_a_flood() {
        let (l, _) = limiter();
        assert_eq!(l.record(7), Decision::Write { suppressed: 0 });
        for _ in 0..10_000 {
            assert_eq!(l.record(7), Decision::Suppress);
        }
    }
}
