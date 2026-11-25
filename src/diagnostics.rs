//! Crash reports and usage counts, through Sentry's Rust SDK (MIT), from release
//! builds only. PRIVACY.md says what is sent, and how to turn it off.
//!
//! - **Only in a release:** the DSN is compiled in only with the `sentry` feature,
//!   which builds from source don't have, and only when the release workflow sets
//!   `LIME_RELEASE`. Anything else sends nothing.
//! - **Off** when `DO_NOT_TRACK` is set in lime's environment to anything but empty,
//!   `0` or `false`.
//! - **Sent:**
//!   - a session per start of lime, ended as crashed if lime stops on an error;
//!   - panics;
//!   - an `unlock` transaction per password sent to a Mac at the pre-boot unlock,
//!     tagged with how it went (`unlocked` or `refused`).
//!
//!   Each carries a random ID made at that start and kept nowhere, and the SDK's
//!   contexts: the kernel's `uname` fields, the architecture and the Rust version.
//! - **Never sent:** the Macs' labels, mDNS names, addresses and host keys, the
//!   unlock accounts and their passwords, the interfaces, the configuration, or
//!   lime's log lines. `server_name`, which the SDK would set to this host's name, is
//!   `lime`.

use std::time::Instant;

/// lime's version as its release names it: `2026.11.25`, or a later release of the
/// same day, `2026.11.25_1`. Cargo can't carry the `_`, so Cargo.toml has the day's
/// number as build metadata, `2026.11.25+1`.
#[cfg_attr(not(feature = "sentry"), allow(dead_code))]
fn version() -> String {
    env!("CARGO_PKG_VERSION").replacen('+', "_", 1)
}

/// Whether a `DO_NOT_TRACK` of `value` asks for no tracking: set to anything but
/// empty, `0` or `false` (in any case), as regulad/Warlock reads it.
#[cfg_attr(not(feature = "sentry"), allow(dead_code))]
fn do_not_track(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        let v = v.trim();
        !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false"))
    })
}

#[cfg(feature = "sentry")]
mod sentry_on {
    use std::time::Instant;

    use sentry::protocol::{SessionStatus, SpanStatus, User};

    /// lime's project's DSN, compiled into a release build alone.
    const DSN: &str = match option_env!("LIME_RELEASE") {
        Some(_) => {
            "https://63bbeef57cbf64adb26cd52a2f6066b0@o4506961510596608.ingest.us.sentry.io/4512494966079488"
        }
        None => "",
    };

    pub struct Guard(#[allow(dead_code)] sentry::ClientInitGuard);

    pub fn start() -> Option<Guard> {
        if DSN.is_empty() || super::do_not_track(std::env::var("DO_NOT_TRACK").ok().as_deref()) {
            return None;
        }
        // Field by field: the struct is non-exhaustive.
        let mut options = sentry::ClientOptions::default().traces_sample_rate(1.0);
        options.dsn = DSN.parse().ok();
        options.release = Some(format!("lime@{}", super::version()).into());
        options.environment = Some("production".into());
        // Without one, the SDK reports this host's name.
        options.server_name = Some("lime".into());
        options.send_default_pii = false;
        // Started below, once the scope has this start's ID.
        options.auto_session_tracking = false;
        let guard = sentry::init(options);
        sentry::configure_scope(|scope| {
            scope.set_user(Some(User {
                id: Some(sentry::types::random_uuid().to_string()),
                ..Default::default()
            }));
        });
        sentry::start_session();
        Some(Guard(guard))
    }

    pub fn failed() {
        sentry::end_session_with_status(SessionStatus::Crashed);
        if let Some(client) = sentry::Hub::current().client() {
            client.flush(Some(std::time::Duration::from_secs(2)));
        }
    }

    pub fn unlock(started: Instant, unlocked: bool) {
        let transaction =
            sentry::start_transaction(sentry::TransactionContext::new("unlock", "lime.unlock"));
        transaction.set_tag("outcome", if unlocked { "unlocked" } else { "refused" });
        transaction.set_status(if unlocked {
            SpanStatus::Ok
        } else {
            SpanStatus::PermissionDenied
        });
        transaction.set_data("seconds", started.elapsed().as_secs_f64().into());
        transaction.finish();
    }
}

/// Diagnostics until dropped, which sends what's left (for at most 2 s).
#[must_use]
pub struct Diagnostics {
    #[cfg(feature = "sentry")]
    _guard: Option<sentry_on::Guard>,
}

/// Starts diagnostics, if this is a release build and `DO_NOT_TRACK` doesn't say no.
pub fn start() -> Diagnostics {
    Diagnostics {
        #[cfg(feature = "sentry")]
        _guard: sentry_on::start(),
    }
}

/// lime is stopping on an error: ends this start's session as crashed, and sends it.
pub fn failed() {
    #[cfg(feature = "sentry")]
    sentry_on::failed();
}

/// A password sent to a Mac at the pre-boot unlock, from `started`, which it took
/// (`unlocked`) or refused.
pub fn unlock(started: Instant, unlocked: bool) {
    #[cfg(feature = "sentry")]
    sentry_on::unlock(started, unlocked);
    #[cfg(not(feature = "sentry"))]
    let _ = (started, unlocked);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_not_track_is_anything_but_empty_zero_or_false() {
        for on in ["1", "true", "yes", " 1 "] {
            assert!(do_not_track(Some(on)), "{on:?}");
        }
        for off in [
            None,
            Some(""),
            Some(" "),
            Some("0"),
            Some("false"),
            Some("FALSE"),
        ] {
            assert!(!do_not_track(off), "{off:?}");
        }
    }

    #[test]
    fn a_later_release_of_the_day_is_named_with_an_underscore() {
        assert!(!version().contains('+'));
    }
}
