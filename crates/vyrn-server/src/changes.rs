//! The change ring: published change events and their bounded buffer.

use tokio::sync::broadcast::{self};
use vyrn_core::change_log;

#[derive(Clone)]
pub(crate) struct ChangeEvent {
    pub(crate) sequence: u64,
    pub(crate) key: Vec<u8>,
    pub(crate) value: Option<Vec<u8>>,
    /// Durable position of this change, when it was published to the change log.
    pub(crate) cursor: Option<change_log::Cursor>,
    /// True when the ring dropped this event's value to stay inside its byte
    /// bound, so `value` is `None` for a change that was NOT a delete.
    ///
    /// Subscribers must not report this as a deletion. They treat it exactly like
    /// a lagged subscription — tell the client to resynchronize — because that is
    /// what it is: a change whose contents this server can no longer supply from
    /// memory. See [`ChangeRing`].
    pub(crate) elided: bool,
}

/// Bytes of change payload the broadcast ring may hold.
///
/// WHY: the ring keeps the last `--write-queue-capacity` events so slow
/// subscribers can catch up, and it keeps them whether or not anybody is
/// subscribed. At the default 4096 events and the 16 MiB `MAX_VALUE_SIZE` that is
/// another ~64 GiB of resident memory reachable by ordinary writes — the same
/// exposure as the write queue, on a structure that exists purely as a
/// convenience for subscribers.
///
/// 64 MiB is far more than any subscriber needs to ride out a scheduling hiccup,
/// and it is bounded regardless of value size.
pub(crate) const CHANGE_RING_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The change broadcast plus enough accounting to bound its memory.
///
/// A `broadcast::Sender` retains the last `capacity` messages and offers no way
/// to ask how much memory that is, so this mirrors the ring: one entry per live
/// message, evicted in the same order the channel evicts. That mirror is exact
/// because tokio's ring holds precisely the most recent `capacity` sends.
///
/// When admitting an event would exceed the byte bound, its VALUE is dropped and
/// `elided` set, rather than dropping the event or blocking the writer. That
/// choice is deliberate:
///
///   - dropping the event would make a subscriber miss a change silently, which
///     is the one failure a change feed must never have;
///   - blocking the commit path on subscriber memory would let one idle
///     subscription stall every writer.
///
/// An elided event still carries its key and sequence, so a subscriber learns
/// that the key changed and is told to resynchronize. Losing the payload is
/// visible and recoverable; losing the notification is neither.
pub(crate) struct ChangeRing {
    pub(crate) sender: broadcast::Sender<ChangeEvent>,
    /// Sizes of the events currently retained, oldest first, with their total.
    /// Never held across an `await`.
    pub(crate) live: std::sync::Mutex<RingBytes>,
    pub(crate) capacity: usize,
}

#[derive(Default)]
pub(crate) struct RingBytes {
    pub(crate) sizes: std::collections::VecDeque<usize>,
    pub(crate) total: usize,
}

impl ChangeRing {
    pub(crate) fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            live: std::sync::Mutex::new(RingBytes::default()),
            capacity,
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<ChangeEvent> {
        self.sender.subscribe()
    }

    /// Publishes one change, eliding its value if the ring is at its byte bound.
    pub(crate) fn send(&self, mut event: ChangeEvent) {
        let value_bytes = event.value.as_ref().map_or(0, Vec::len);
        let mut bytes = event.key.len() + value_bytes;
        if let Ok(mut live) = self.live.lock() {
            if live.total + bytes > CHANGE_RING_MAX_BYTES && value_bytes > 0 {
                /* Keep the notification, drop the payload. A key alone is at
                 * most `MAX_KEY_SIZE`, so even an all-elided ring stays bounded
                 * by capacity × 64 KiB. */
                event.value = None;
                event.elided = true;
                bytes = event.key.len();
            }
            live.sizes.push_back(bytes);
            live.total = live.total.saturating_add(bytes);
            // Mirror the channel's eviction: one message leaves for each that
            // arrives once the ring is full.
            while live.sizes.len() > self.capacity {
                let evicted = live.sizes.pop_front().unwrap_or(0);
                live.total = live.total.saturating_sub(evicted);
            }
        }
        /* A send with no subscribers is not an error: the ring exists for
         * whoever attaches next, and the commit path must not care. */
        let _ = self.sender.send(event);
    }
}
