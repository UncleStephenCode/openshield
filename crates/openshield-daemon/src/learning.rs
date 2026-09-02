use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use openshield_core::Mode;
use tracing::{debug, info, warn};

use crate::backend::FirewallObserver;
use crate::engine::SharedEngine;

const COUNTER_INTERVAL: Duration = Duration::from_secs(1);
const MONITOR_TICK: Duration = Duration::from_millis(50);
const REPEATED_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(30);
const POLICY_REPAIR_INTERVAL: Duration = Duration::from_secs(30);

pub fn spawn_monitor<O>(
    observer: O,
    engine: SharedEngine,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>>
where
    O: FirewallObserver + 'static,
{
    thread::Builder::new()
        .name("openshield-firewall-monitor".to_owned())
        .spawn(move || {
            let mut observer = observer;
            monitor_loop(&mut observer, &engine, &shutdown);
        })
        .context("cannot spawn firewall monitor")
}

fn monitor_loop<O>(observer: &mut O, engine: &SharedEngine, shutdown: &AtomicBool)
where
    O: FirewallObserver,
{
    let mut next_counter_poll = Instant::now();
    let mut counter_errors = ErrorGate::default();

    while !shutdown.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= next_counter_poll {
            poll_counters(observer, engine, shutdown, &mut counter_errors);
            next_counter_poll = Instant::now() + COUNTER_INTERVAL;
        }
        thread::sleep(MONITOR_TICK);
    }
}

fn poll_counters<O>(
    observer: &mut O,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    errors: &mut ErrorGate,
) where
    O: FirewallObserver,
{
    let Some((revision, _mode)) = policy_identity(engine) else {
        return;
    };
    match observer.policy_observation() {
        Ok(counters) => {
            errors.recovered("firewall counter polling recovered");
            let Ok(mut engine) = engine.lock() else {
                errors.report("policy engine mutex is poisoned while publishing counters");
                return;
            };
            let _changed = engine.publish_counters_if_current(revision, counters);
        }
        Err(error) => {
            errors.report(&format!(
                "cannot verify bounded firewall policy observation: {error:#}"
            ));
            repair_after_observation_failure(engine, shutdown, revision, errors);
        }
    }
}

fn repair_after_observation_failure(
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    revision: u64,
    errors: &mut ErrorGate,
) {
    if shutdown.load(Ordering::Acquire) || !errors.should_attempt_repair() {
        return;
    }
    let Ok(mut engine) = engine.lock() else {
        errors.report("policy engine mutex is poisoned during firewall repair");
        return;
    };
    // Shutdown installs a non-persistent BlockAll quarantine under this same
    // mutex. Never race it by restoring the saved runtime mode afterward.
    if shutdown.load(Ordering::Acquire) {
        return;
    }
    match engine.repair_policy(revision) {
        Ok(true) => info!(
            revision,
            "reinstalled firewall policy after observation failure"
        ),
        Ok(false) => debug!(
            observed_revision = revision,
            current_revision = engine.revision(),
            "skipped stale firewall repair request"
        ),
        Err(repair_error) => {
            errors.report(&format!(
                "firewall repair failed ({:?}): {}",
                repair_error.code, repair_error.message
            ));
            if engine.restart_required() {
                shutdown.store(true, Ordering::Release);
            }
        }
    }
}

fn policy_identity(engine: &SharedEngine) -> Option<(u64, Mode)> {
    if let Ok(engine) = engine.lock() {
        Some((engine.revision(), engine.mode()))
    } else {
        warn!("policy engine mutex is poisoned; firewall observation paused");
        None
    }
}

#[derive(Debug, Default)]
struct ErrorGate {
    last_log: Option<Instant>,
    last_repair: Option<Instant>,
    failing: bool,
}

impl ErrorGate {
    fn report(&mut self, message: &str) {
        let now = Instant::now();
        if self
            .last_log
            .is_none_or(|last| now.duration_since(last) >= REPEATED_ERROR_LOG_INTERVAL)
        {
            warn!(message, "non-fatal firewall observation failure");
            self.last_log = Some(now);
        }
        self.failing = true;
    }

    fn recovered(&mut self, message: &str) {
        if self.failing {
            debug!(message, "firewall observation recovered");
        }
        self.failing = false;
        self.last_log = None;
        self.last_repair = None;
    }

    fn should_attempt_repair(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last_repair
            .is_some_and(|last| now.duration_since(last) < POLICY_REPAIR_INTERVAL)
        {
            return false;
        }
        self.last_repair = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    #[test]
    fn repeated_observer_errors_are_rate_limited() -> Result<()> {
        let mut gate = ErrorGate::default();
        gate.report("first");
        let first = gate
            .last_log
            .ok_or_else(|| anyhow!("first failure was not recorded"))?;
        gate.report("second");
        assert_eq!(gate.last_log, Some(first));
        assert!(gate.should_attempt_repair());
        assert!(!gate.should_attempt_repair());
        gate.recovered("recovered");
        assert!(gate.last_log.is_none());
        assert!(gate.last_repair.is_none());
        assert!(!gate.failing);
        Ok(())
    }
}
