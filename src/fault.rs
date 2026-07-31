use rustix::io::Errno;
#[cfg(feature = "fault-injection")]
use std::env;

// a real process death, not a simulated error return, so recovery is exercised
// against the same state a power loss would leave. compiled out entirely unless
// the feature is on, so the shipped binary cannot reach it.
#[cfg(feature = "fault-injection")]
pub(crate) fn fault_point(name: &str) {
    if env::var("FURNISH_FAULT_POINT").ok().as_deref() == Some(name) {
        std::process::abort();
    }
}

#[cfg(not(feature = "fault-injection"))]
#[inline(always)]
pub(crate) fn fault_point(_name: &str) {}

#[cfg(feature = "fault-injection")]
pub(crate) fn reverse_exchange_restore_fault() -> std::result::Result<(), Errno> {
    if env::var("FURNISH_FAULT_POINT").ok().as_deref() == Some("reverse-exchange-restore-failed") {
        return Err(Errno::IO);
    }
    Ok(())
}

#[cfg(not(feature = "fault-injection"))]
#[inline(always)]
pub(crate) fn reverse_exchange_restore_fault() -> std::result::Result<(), Errno> {
    Ok(())
}
