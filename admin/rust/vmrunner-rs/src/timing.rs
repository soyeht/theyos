//! timing.rs — Structured timing and phase tracking for VM operations

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Tracks timing for multiple phases of an operation
#[derive(Debug, Clone)]
pub struct PhaseTimer {
    instance_id: String,
    phases: Vec<(String, Duration)>,
    current_phase: Option<(String, Instant)>,
    start_time: Instant,
}

impl PhaseTimer {
    /// Create a new timer for an instance
    pub fn new(instance_id: impl Into<String>) -> Self {
        Self {
            instance_id: instance_id.into(),
            phases: Vec::new(),
            current_phase: None,
            start_time: Instant::now(),
        }
    }

    /// Start a new phase, ending the previous one if any
    pub fn start_phase(&mut self, name: impl Into<String>) {
        let name = name.into();

        // End previous phase if exists
        if let Some((prev_name, start)) = self.current_phase.take() {
            let elapsed = start.elapsed();
            self.phases.push((prev_name, elapsed));
        }

        self.current_phase = Some((name, Instant::now()));
    }

    /// End the current phase
    pub fn end_phase(&mut self) {
        if let Some((name, start)) = self.current_phase.take() {
            let elapsed = start.elapsed();
            self.phases.push((name, elapsed));
        }
    }

    /// Get total elapsed time
    #[must_use]
    pub fn total_elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get all completed phases
    #[must_use]
    pub fn phases(&self) -> &[(String, Duration)] {
        &self.phases
    }

    /// Format as structured JSON log entry
    #[must_use]
    pub fn to_json_log(&self) -> String {
        use serde_json::json;

        let phases_map: HashMap<String, u128> = self
            .phases
            .iter()
            .map(|(name, dur)| (name.clone(), dur.as_millis()))
            .collect();

        let obj = json!({
            "vm_timing": {
                "instance_id": self.instance_id,
                "total_ms": self.total_elapsed().as_millis(),
                "phases": phases_map
            }
        });

        obj.to_string()
    }

    /// Log all phases in a human-readable format
    pub fn log_summary(&self) {
        let total = self.total_elapsed();
        tracing::info!(
            "[vmrunner-timing] {} total: {}ms",
            self.instance_id,
            total.as_millis()
        );

        for (name, duration) in &self.phases {
            // NOTE: u128→f64 cast is intentional; millisecond precision is sufficient
            // for timing display and any loss of precision at extreme values is acceptable.
            #[allow(clippy::cast_precision_loss)]
            let pct = if total.as_millis() > 0 {
                (duration.as_millis() as f64 / total.as_millis() as f64) * 100.0
            } else {
                0.0
            };
            tracing::info!(
                "[vmrunner-timing]   {}: {}ms ({:.1}%)",
                name,
                duration.as_millis(),
                pct
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn phase_timer_tracks_durations() {
        let mut timer = PhaseTimer::new("test-instance");

        timer.start_phase("phase1");
        sleep(Duration::from_millis(10));
        timer.start_phase("phase2");
        sleep(Duration::from_millis(10));
        timer.end_phase();

        assert!(timer.total_elapsed().as_millis() >= 20);
        assert_eq!(timer.phases().len(), 2);
    }

    #[test]
    fn phase_timer_produces_valid_json() {
        let mut timer = PhaseTimer::new("test-instance");
        timer.start_phase("phase1");
        timer.end_phase();

        let json = timer.to_json_log();
        assert!(json.contains("vm_timing"));
        assert!(json.contains("test-instance"));
        assert!(json.contains("total_ms"));
        assert!(json.contains("phase1"));
    }
}
