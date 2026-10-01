// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The client's connection renewal (spec 0381). It renews its own
//! connection between steps, so in normal play no call races a close
//! (`needs_renewal`). A server run with `--max-connection-age` closes
//! connections on its own clock, which a call can race; tonic reports most
//! HTTP/2 failures as `Internal: h2 protocol error: http2 error`, whatever
//! the cause, and the `h2::Error` in the status's source chain tells such a
//! race from a real fault.

use std::error::Error;
use std::time::{Duration, Instant};

/// Whether a connection created at `created` is due for renewal at `now`
/// (spec 0381 S7): it is `period` old or more. A zero period never renews.
pub fn needs_renewal(created: Instant, now: Instant, period: Duration) -> bool {
    !period.is_zero() && now.saturating_duration_since(created) >= period
}

/// The HTTP/2 error behind a status, if any (spec 0381 S1): the first error
/// in the status's source chain that is an `h2::Error`.
pub fn h2_error(status: &tonic::Status) -> Option<&h2::Error> {
    let mut source = status.source();
    while let Some(err) = source {
        if let Some(h2) = err.downcast_ref::<h2::Error>() {
            return Some(h2);
        }
        source = err.source();
    }
    None
}

/// The HTTP/2 condition behind a status, as `[h2 <kind> <REASON> <origin>]`
/// (spec 0381 S2), or `None` when the status has no `h2::Error` behind it.
pub fn h2_note(status: &tonic::Status) -> Option<String> {
    let err = h2_error(status)?;
    let kind = if err.is_go_away() {
        "GOAWAY"
    } else if err.is_reset() {
        "RST_STREAM"
    } else if err.is_io() {
        "io"
    } else {
        "reason"
    };
    let origin = if err.is_remote() {
        "remote"
    } else if err.is_library() {
        "library"
    } else {
        "local"
    };
    Some(match err.reason() {
        Some(reason) => format!("[h2 {kind} {reason:?} {origin}]"),
        None => format!("[h2 {kind} {origin}]"),
    })
}

/// Whether a failed step raced a connection renewal, so that one retry, on
/// the new connection, is safe and expected (spec 0381 S4). Step is a pure
/// computation, so a retry never changes the game.
///
/// Besides a connection that failed outright (`Unavailable`, or `Unknown`
/// with "transport error"), this is the one condition measured for the race
/// (spec 0381 S3): a GOAWAY with NO_ERROR sent by the server, its graceful
/// close at `--max-connection-age`. A GOAWAY means the server did not handle
/// the request (RFC 9113 §6.8). Any other HTTP/2 failure is a real fault and
/// is not retried.
pub fn is_renewal_race(status: &tonic::Status) -> bool {
    use tonic::Code;
    match status.code() {
        Code::Unavailable => true,
        Code::Unknown => status.message().contains("transport error"),
        Code::Internal => h2_error(status).is_some_and(|err| {
            err.is_go_away() && err.is_remote() && err.reason() == Some(h2::Reason::NO_ERROR)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare_reason(reason: h2::Reason) -> tonic::Status {
        tonic::Status::from_error(Box::new(h2::Error::from(reason)))
    }

    #[test]
    fn renewal_is_due_at_the_period() {
        let t = Instant::now();
        let five = Duration::from_secs(5);
        assert!(!needs_renewal(t, t, five));
        assert!(!needs_renewal(t, t + Duration::from_millis(4999), five));
        assert!(needs_renewal(t, t + five, five));
        assert!(needs_renewal(t, t + Duration::from_secs(60), five));
        assert!(!needs_renewal(
            t,
            t + Duration::from_secs(60),
            Duration::ZERO
        ));
    }

    #[test]
    fn h2_note_names_the_condition() {
        let status = bare_reason(h2::Reason::PROTOCOL_ERROR);
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(
            h2_note(&status).as_deref(),
            Some("[h2 reason PROTOCOL_ERROR local]")
        );
        assert_eq!(h2_note(&tonic::Status::internal("boom")), None);
    }

    #[test]
    fn a_non_renewal_failure_is_not_retried() {
        assert!(!is_renewal_race(&bare_reason(h2::Reason::PROTOCOL_ERROR)));
        assert!(!is_renewal_race(&bare_reason(h2::Reason::NO_ERROR)));
        assert!(!is_renewal_race(&tonic::Status::internal("boom")));
        assert!(is_renewal_race(&tonic::Status::unavailable("gone")));
        assert!(is_renewal_race(&tonic::Status::unknown(
            "transport error: connection reset"
        )));
    }
}
