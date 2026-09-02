//! Admission limits: the write-payload byte budget and auth throttling.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use vyrn_core::BatchOperation;

use crate::DocumentWrite;

/// Total bytes of pending write payload allowed in the pipeline at once.
///
/// WHY A BYTE BOUND AND NOT JUST A SLOT COUNT: `--write-queue-capacity` bounds
/// the number of queued requests, not their size. At the default 4096 slots and
/// the 16 MiB `MAX_VALUE_SIZE`, a queue that is merely full holds up to ~64 GiB
/// of values — and it fills exactly when the pipeline is slowest, because the
/// write worker stalls behind a checkpoint or a slow barrier while clients keep
/// submitting. The process is then killed by the OOM killer at the worst possible
/// moment: mid-checkpoint, with a full WAL to replay.
///
/// 256 MiB is chosen to be far above any legitimate burst (it is 16 concurrent
/// maximum-size values, or tens of thousands of ordinary ones) while keeping the
/// worst case a number a host can actually hold. Exceeding it makes writers wait
/// rather than fail: back-pressure is the correct response to a slow disk, and a
/// client that waits gets its commit, where a client that is refused has to
/// decide whether retrying is safe.
pub(crate) const WRITE_QUEUE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Consecutive failed authentications from one address before it is locked out.
pub(crate) const AUTH_FAILURE_LIMIT: u32 = 10;

/// How long a locked-out address stays refused, and how long an idle address's
/// failure count is remembered.
pub(crate) const AUTH_LOCKOUT: Duration = Duration::from_secs(60);

/// Addresses tracked at once, bounding the throttle's own memory.
pub(crate) const AUTH_THROTTLE_CAPACITY: usize = 4096;

/// Reserves queue memory for one pending write, releasing it on drop.
///
/// A permit is acquired before the request enters the channel and held until the
/// client's answer has been received, which is the whole interval during which
/// the payload occupies memory: the channel slot, then the write worker's batch,
/// then the `PendingFlush` awaiting its barrier. Releasing any earlier would
/// under-count exactly the backlog this bounds.
///
/// Tied to a semaphore rather than a counter so that an over-budget writer waits
/// instead of failing, and so the release cannot be forgotten on an error path —
/// dropping the guard is the release, and every early return drops it.
pub(crate) struct WriteBudget {
    /// `None` for requests too large to ever fit the budget on their own; they
    /// proceed unmetered rather than deadlocking. A single request cannot exceed
    /// `MAX_VALUE_SIZE` plus a key, which is far under the budget, so this is
    /// unreachable in practice and exists so the arithmetic has no failure mode.
    pub(crate) _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl WriteBudget {
    /// Waits until `bytes` of queue budget is available.
    pub(crate) async fn acquire(budget: &Arc<Semaphore>, bytes: usize) -> Self {
        // Clamped because `acquire_many` takes a u32 and panics if the request
        // exceeds the semaphore's total.
        let permits = bytes.min(WRITE_QUEUE_MAX_BYTES) as u32;
        let permit = Arc::clone(budget)
            .acquire_many_owned(permits.max(1))
            .await
            .ok();
        Self { _permit: permit }
    }
}

/// Queue-memory cost of one write request.
///
/// Counts payload only. The per-request overhead is a fixed few hundred bytes
/// against a budget measured in hundreds of megabytes, so tracking it would add
/// arithmetic without changing when the bound trips.
pub(crate) fn operation_bytes(operation: &BatchOperation) -> usize {
    match operation {
        BatchOperation::Put(key, value) => key.len() + value.len(),
        BatchOperation::Delete(key) => key.len(),
    }
}

pub(crate) fn document_write_bytes(request: &DocumentWrite) -> usize {
    match request {
        DocumentWrite::CreateCollection {
            collection,
            indexes,
        } => collection.len() + indexes.iter().map(|index| index.field.len()).sum::<usize>(),
        DocumentWrite::Put {
            collection,
            id,
            document,
        } => collection.len() + id.len() + document.len(),
        DocumentWrite::Delete { collection, id } => collection.len() + id.len(),
    }
}

/// Per-address failed-authentication throttle.
///
/// WHY THIS EXISTS: verifying a password is deliberately expensive — that is what
/// makes the stored hash worth storing. Argon2 with the default parameters costs
/// tens of milliseconds and a chunk of memory per attempt, so an unauthenticated
/// peer could pin server CPU and memory just by guessing, and the guesses are
/// free for it. `--max-auth-jobs` already caps how many verifications run at
/// once, but a cap alone does not end the attack: it converts CPU exhaustion into
/// a queue every legitimate client also waits in.
///
/// So refusal has to happen BEFORE the verification. After
/// `AUTH_FAILURE_LIMIT` consecutive failures an address is refused outright for
/// `AUTH_LOCKOUT`, without touching Argon2 — which is also why the correct
/// password is refused during a lockout, and why that is the observable proof
/// the check runs early enough to matter.
///
/// Keyed on IP, not on address-with-port: a source port changes per connection,
/// so counting it would reset on every attempt and never trip.
///
/// SCOPE, stated plainly: this raises the cost of online guessing against a
/// single-credential server. It is not a defence against a distributed attacker,
/// who simply spreads attempts across addresses, and against a spoofed source it
/// is a self-inflicted denial of service for the address being impersonated.
/// The real fix for both is per-principal credentials with revocation, which
/// this server does not have (see the deferred list in `todo.md`).
pub(crate) struct AuthThrottle {
    /// Sorted by nothing — small, capacity-bounded, and only touched on the
    /// handshake path, so a plain map under a mutex is cheaper than anything
    /// cleverer. Never held across an `await`.
    pub(crate) addresses: std::sync::Mutex<HashMap<IpAddr, AuthFailures>>,
}

pub(crate) struct AuthFailures {
    pub(crate) consecutive: u32,
    /// When the most recent failure was recorded, so entries expire.
    pub(crate) last: Instant,
}

impl AuthThrottle {
    pub(crate) fn new() -> Self {
        Self {
            addresses: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// True when this address is currently locked out.
    pub(crate) fn is_locked_out(&self, address: IpAddr) -> bool {
        let Ok(mut addresses) = self.addresses.lock() else {
            /* A poisoned throttle must not become an authentication bypass, but
             * it must not lock everyone out either: the mutex only guards a
             * counter, and a panic while holding it cannot corrupt anything a
             * later attempt depends on. Fail open on the throttle and let the
             * password check decide, which is the pre-throttle behaviour. */
            return false;
        };
        match addresses.get(&address) {
            Some(failures) if failures.consecutive >= AUTH_FAILURE_LIMIT => {
                if failures.last.elapsed() < AUTH_LOCKOUT {
                    true
                } else {
                    // The lockout expired: forget it and let this attempt run.
                    addresses.remove(&address);
                    false
                }
            }
            _ => false,
        }
    }

    pub(crate) fn record_failure(&self, address: IpAddr) {
        let Ok(mut addresses) = self.addresses.lock() else {
            return;
        };
        let now = Instant::now();
        // Drop expired entries before inserting, so a long run of one-off
        // failures from many addresses cannot grow this map without bound.
        if addresses.len() >= AUTH_THROTTLE_CAPACITY {
            addresses.retain(|_, failures| failures.last.elapsed() < AUTH_LOCKOUT);
            /* Still full: every tracked address is live, so this is either a
             * broad attack or a very large legitimate fleet. Refusing to track
             * the new address is the safe direction — it gets the ordinary
             * password check, and the addresses already failing stay locked. */
            if addresses.len() >= AUTH_THROTTLE_CAPACITY {
                return;
            }
        }
        let entry = addresses.entry(address).or_insert(AuthFailures {
            consecutive: 0,
            last: now,
        });
        // Saturating so a very long attack cannot wrap the counter back under
        // the limit and release the lockout.
        entry.consecutive = entry.consecutive.saturating_add(1);
        entry.last = now;
    }

    /// Clears an address's history after a successful authentication.
    pub(crate) fn record_success(&self, address: IpAddr) {
        if let Ok(mut addresses) = self.addresses.lock() {
            addresses.remove(&address);
        }
    }
}
