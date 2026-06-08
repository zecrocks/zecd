//! Exponential backoff with full jitter, used to pace lightwalletd reconnect attempts so a
//! down upstream is retried gently (and without a thundering herd) rather than on a tight loop.

use std::time::Duration;

use rand::Rng;

/// Exponential backoff with full jitter. [`next_delay`](Backoff::next_delay) returns the next
/// wait and advances the attempt counter; [`reset`](Backoff::reset) returns to the base delay
/// after a successful connection.
#[derive(Clone, Debug)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Backoff { base, max, attempt: 0 }
    }

    /// The (pre-jitter) ceiling for the current attempt: `min(base * 2^attempt, max)`. The shift
    /// is clamped and the multiply is checked so high attempt counts saturate at `max` rather
    /// than overflow/panic.
    pub fn cap(&self) -> Duration {
        match self.base.checked_mul(1u32 << self.attempt.min(31)) {
            Some(d) => d.min(self.max),
            None => self.max,
        }
    }

    /// Return a random wait in `[0, cap]` (full jitter) and advance the attempt counter.
    pub fn next_delay(&mut self) -> Duration {
        let cap_millis = self.cap().as_millis() as u64;
        self.attempt = self.attempt.saturating_add(1);
        let jittered = rand::thread_rng().gen_range(0..=cap_millis);
        Duration::from_millis(jittered)
    }

    /// Reset to the base delay (call after a successful connection).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_grows_then_saturates() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        // 1, 2, 4, 8, 16, 32, then clamped to max (60) thereafter.
        for exp in [1u64, 2, 4, 8, 16, 32, 60, 60, 60] {
            assert_eq!(b.cap(), Duration::from_secs(exp));
            let _ = b.next_delay();
        }
    }

    #[test]
    fn jitter_within_bounds() {
        let mut b = Backoff::new(Duration::from_millis(50), Duration::from_secs(10));
        for _ in 0..1000 {
            let cap = b.cap();
            let d = b.next_delay();
            assert!(d <= cap, "delay {d:?} exceeded cap {cap:?}");
        }
    }

    #[test]
    fn reset_returns_to_base() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        for _ in 0..5 {
            let _ = b.next_delay();
        }
        assert_ne!(b.cap(), Duration::from_secs(1));
        b.reset();
        assert_eq!(b.cap(), Duration::from_secs(1));
    }

    #[test]
    fn no_overflow_at_high_attempt() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        for _ in 0..64 {
            let d = b.next_delay();
            assert!(d <= Duration::from_secs(60));
        }
        assert_eq!(b.cap(), Duration::from_secs(60));
    }
}
