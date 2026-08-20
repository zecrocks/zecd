//! A shared wall-clock throttle for progress heartbeats on long-running passes.
//!
//! Three passes legitimately run for minutes to hours (the enhancement drain, the A18
//! transparent pre-exposure, and gap maintenance while recording transparent receives), and
//! each needs the same heartbeat shape: at most one line per interval, reporting a *rolling*
//! rate over the window since the previous line rather than a drifting cumulative average.
//! This type is that shared arithmetic; the callers own their message text and any extra
//! stats (percentages, ETAs).

use std::time::{Duration, Instant};

/// Throttles a progress heartbeat to at most one report per `interval`.
///
/// Construct it when the pass starts (which arms the first window silently, so short passes
/// never log at all) and call [`ProgressThrottle::tick`] with the running completion count on
/// every unit of work; a `Some` return means "log now" and carries the window's stats.
#[derive(Debug)]
pub struct ProgressThrottle {
    interval: Duration,
    started: Instant,
    last_report: Instant,
    last_count: u64,
}

/// The stats for one due heartbeat: what happened since the previous reported line.
#[derive(Debug, PartialEq)]
pub struct ProgressWindow {
    /// Units of work completed in this window.
    pub did: u64,
    /// Window length in seconds (time since the previous report).
    pub window_secs: f64,
    /// Rolling rate over the window, in units/second. `0.0` when the window length is zero -
    /// never `inf`/NaN.
    pub rate: f64,
    /// Seconds since the pass began.
    pub elapsed_secs: f64,
}

impl ProgressThrottle {
    pub fn new(interval: Duration, initial_count: u64) -> Self {
        Self::new_at(interval, initial_count, Instant::now())
    }

    fn new_at(interval: Duration, initial_count: u64, now: Instant) -> Self {
        Self {
            interval,
            started: now,
            last_report: now,
            last_count: initial_count,
        }
    }

    /// When at least `interval` has passed since the previous report, return the window's
    /// stats and re-arm; otherwise `None`. `count` is the pass's running total (monotonic;
    /// a regression is clamped to a zero-work window rather than underflowing).
    pub fn tick(&mut self, count: u64) -> Option<ProgressWindow> {
        self.tick_at(count, Instant::now())
    }

    fn tick_at(&mut self, count: u64, now: Instant) -> Option<ProgressWindow> {
        let window = now.saturating_duration_since(self.last_report);
        if window < self.interval {
            return None;
        }
        let window_secs = window.as_secs_f64();
        let did = count.saturating_sub(self.last_count);
        let rate = if window_secs > 0.0 {
            did as f64 / window_secs
        } else {
            0.0
        };
        let report = ProgressWindow {
            did,
            window_secs,
            rate,
            elapsed_secs: now.saturating_duration_since(self.started).as_secs_f64(),
        };
        self.last_report = now;
        self.last_count = count;
        Some(report)
    }

    /// Seconds since the pass began, for a completion line.
    pub fn elapsed_secs(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(30);

    #[test]
    fn first_window_is_armed_silently_and_reports_only_after_the_interval() {
        let t0 = Instant::now();
        let mut t = ProgressThrottle::new_at(INTERVAL, 0, t0);
        // Inside the interval: quiet, however much work happened.
        assert_eq!(t.tick_at(500, t0 + Duration::from_secs(29)), None);
        // Past it: one report covering the whole window since construction.
        let w = t
            .tick_at(600, t0 + Duration::from_secs(30))
            .expect("interval elapsed");
        assert_eq!(w.did, 600);
        assert!((w.window_secs - 30.0).abs() < 1e-9);
        assert!((w.rate - 20.0).abs() < 1e-9);
        assert!((w.elapsed_secs - 30.0).abs() < 1e-9);
    }

    #[test]
    fn rate_is_a_rolling_window_not_a_cumulative_average() {
        let t0 = Instant::now();
        let mut t = ProgressThrottle::new_at(INTERVAL, 0, t0);
        t.tick_at(3000, t0 + Duration::from_secs(30)).unwrap();
        // Second window is much slower; the rate must reflect it alone.
        let w = t.tick_at(3030, t0 + Duration::from_secs(60)).unwrap();
        assert_eq!(w.did, 30);
        assert!((w.rate - 1.0).abs() < 1e-9);
        assert!((w.elapsed_secs - 60.0).abs() < 1e-9);
    }

    #[test]
    fn initial_count_offsets_the_first_window() {
        // Resuming a pass at 1000 done must not count the resumed-past work as this run's.
        let t0 = Instant::now();
        let mut t = ProgressThrottle::new_at(INTERVAL, 1000, t0);
        let w = t.tick_at(1010, t0 + INTERVAL).unwrap();
        assert_eq!(w.did, 10);
    }

    #[test]
    fn zero_length_window_and_count_regression_are_guarded() {
        let t0 = Instant::now();
        let mut t = ProgressThrottle::new_at(Duration::ZERO, 100, t0);
        let w = t.tick_at(50, t0).expect("zero interval is always due");
        // Count went backwards and no time passed: no underflow, no inf/NaN.
        assert_eq!(w.did, 0);
        assert_eq!(w.rate, 0.0);
        assert!(w.rate.is_finite());
    }
}
