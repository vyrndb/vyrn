//! Automatic failover: epoch fencing plus quorum election.
//!
//! ## The safety argument, in full
//!
//! Failover requires `--cluster` naming ALL members (N >= 3) and
//! `--replication-min-acks >= floor(N/2)` — with the primary itself, every
//! acknowledged write is durable on a MAJORITY of the membership. An election
//! needs a majority of the same membership, so every election majority
//! intersects every acknowledgement majority in at least one member. A vote
//! is granted only to a candidate whose durable LSN is at or past the
//! voter's, so the intersecting member forces any electable candidate to
//! hold every acknowledged write. Epochs — persisted BEFORE they are acted
//! on — fence the loser: a member that granted a vote in epoch E refuses
//! streams and acks from every epoch below E, so a deposed primary can
//! neither feed a replica nor assemble the quorum its own acknowledgements
//! require. It steps down instead (`Deposed`), and rejoins as a replica.
//!
//! What this deliberately does NOT provide: client redirection (clients
//! reconnect and discover the leader through `/health/ready`'s role report
//! or their own retry against the member list) and preservation of writes
//! that were never acknowledged (a quorum never held them; the client was
//! told so).
//!
//! Two-member clusters are refused at startup: with N = 2 a majority is 2,
//! so the surviving member can never elect itself — and lowering the bar to
//! 1 would let BOTH sides of a partition lead at once. That is split-brain
//! by construction, and no timeout tuning fixes it; use a third member.

use crate::epoch::EpochStore;
use anyhow::{bail, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One `--cluster` entry: a member's name and the URL its peers reach it at.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub url: String,
}

/// Parses `name=vyrn://user@host:port/db,name=...`, refusing shapes the
/// safety argument does not cover.
pub fn parse_cluster(spec: &str, self_name: &str, min_acks: usize) -> Result<Vec<Member>> {
    let mut members = Vec::new();
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, url)) = entry.split_once('=') else {
            bail!("--cluster entries are name=vyrn://... (got {entry:?})");
        };
        if members.iter().any(|member: &Member| member.name == name) {
            bail!("--cluster names {name:?} twice");
        }
        members.push(Member {
            name: name.to_owned(),
            url: url.to_owned(),
        });
    }
    let count = members.len();
    if count < 3 {
        bail!(
            "automatic failover requires at least 3 cluster members, got {count}. With 2, a \
             majority is 2, so a survivor could never elect itself — and lowering that bar \
             would let both sides of a partition lead at once (split-brain). Use a third \
             member, or omit --cluster and promote manually as documented in \
             docs/replication.md."
        );
    }
    if !members.iter().any(|member| member.name == self_name) {
        bail!("--cluster-self {self_name:?} is not in the --cluster list");
    }
    let majority = count / 2; // acks besides the primary itself
    if min_acks < majority {
        bail!(
            "automatic failover with {count} members requires --replication-min-acks >= \
             {majority}: acknowledged writes must reach a majority (the primary plus \
             {majority} acks) or an elected leader could be missing them. Got {min_acks}."
        );
    }
    Ok(members)
}

/// Votes (including the candidate's own) needed to lead `member_count`.
pub fn votes_needed(member_count: usize) -> usize {
    member_count / 2 + 1
}

/// What this node currently is. Roles only ever move Primary -> Deposed and
/// Follower -> Primary (through an election); a deposed primary rejoins as a
/// follower only through operator restart with --replica-of, which is the
/// rebuild path divergence requires anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Follower,
    /// A primary that saw a higher epoch or lost its lease: it refuses
    /// writes and acknowledgements, forever, until an operator restarts it.
    Deposed,
}

/// Shared failover state: the persisted epochs, the role, and the liveness
/// signal elections key off.
pub struct Failover {
    pub members: Vec<Member>,
    pub self_name: String,
    epochs: Mutex<EpochStore>,
    /// Cached copy of the persisted current epoch, readable without the lock
    /// on hot paths (stream frames, write guards).
    current_epoch: AtomicU64,
    role: Mutex<Role>,
    deposed: AtomicBool,
    /// When a follower last heard from a live primary (any stream frame),
    /// and when a primary last held a quorum. Both feed the same timers.
    last_heard: Mutex<Instant>,
    pub lease: Duration,
    pub election_timeout: Duration,
}

impl Failover {
    pub fn new(
        members: Vec<Member>,
        self_name: String,
        epochs: EpochStore,
        starts_as_primary: bool,
        lease: Duration,
        election_timeout: Duration,
    ) -> Self {
        let current = epochs.current;
        Self {
            members,
            self_name,
            epochs: Mutex::new(epochs),
            current_epoch: AtomicU64::new(current),
            role: Mutex::new(if starts_as_primary {
                Role::Primary
            } else {
                Role::Follower
            }),
            deposed: AtomicBool::new(false),
            last_heard: Mutex::new(Instant::now()),
            lease,
            election_timeout,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Acquire)
    }

    pub fn role(&self) -> Role {
        if self.deposed.load(Ordering::Acquire) {
            return Role::Deposed;
        }
        *self.role.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn heard_from_leader(&self) {
        let mut last = self
            .last_heard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last = Instant::now();
    }

    pub fn silence(&self) -> Duration {
        self.last_heard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .elapsed()
    }

    /// Adopts a higher epoch seen anywhere (a vote request, a stream, a vote
    /// response). Persisted before this returns, and a primary that adopts a
    /// higher epoch is DEPOSED by it: someone won an election it did not
    /// stand in, so acknowledging anything further would be a second writer.
    pub fn observe_epoch(&self, epoch: u64) -> Result<()> {
        if epoch <= self.epoch() {
            return Ok(());
        }
        {
            let mut epochs = self
                .epochs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            epochs.advance(epoch, false)?;
            self.current_epoch.store(epochs.current, Ordering::Release);
        }
        if *self.role.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) == Role::Primary {
            self.deposed.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Grants or refuses a vote. The grant is durable before it is answered —
    /// a vote this node could forget is a vote it could cast twice.
    pub fn consider_vote(&self, epoch: u64, candidate_lsn: u64, own_lsn: u64) -> Result<bool> {
        // Seeing the candidacy at all deposes a primary at a lower epoch,
        // whether or not the vote is granted.
        self.observe_epoch(epoch)?;
        let mut epochs = self
            .epochs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let granted = epoch > epochs.voted && candidate_lsn >= own_lsn;
        if granted {
            epochs.advance(epoch, true)?;
            self.current_epoch.store(epochs.current, Ordering::Release);
        }
        Ok(granted)
    }

    /// Begins a candidacy: persist a new epoch (voting for self) and return
    /// it. The caller gathers the remaining votes.
    pub fn stand(&self) -> Result<u64> {
        let mut epochs = self
            .epochs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let epoch = epochs.current + 1;
        epochs.advance(epoch, true)?;
        self.current_epoch.store(epochs.current, Ordering::Release);
        Ok(epoch)
    }

    /// The candidate won: this node leads at `epoch`.
    pub fn promote(&self) {
        let mut role = self
            .role
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *role = Role::Primary;
        self.heard_from_leader();
    }

    /// A primary that could not hold a quorum for a full lease self-fences:
    /// its acknowledgements would promise a durability it cannot deliver,
    /// and an election it cannot see may already have replaced it.
    pub fn step_down(&self) {
        self.deposed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> EpochStore {
        EpochStore::open(tempfile::tempdir().unwrap().path()).unwrap()
    }

    #[test]
    fn cluster_shapes_the_safety_argument_rejects_are_refused() {
        assert!(parse_cluster("a=u,b=u2", "a", 1).is_err(), "2 members");
        assert!(parse_cluster("a=u,b=u2,c=u3", "a", 0).is_err(), "min-acks 0");
        assert!(parse_cluster("a=u,b=u2,c=u3", "d", 1).is_err(), "self absent");
        assert!(parse_cluster("a=u,a=u2,c=u3", "a", 1).is_err(), "duplicate");
        let members = parse_cluster("a=u,b=u2,c=u3", "a", 1).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(votes_needed(3), 2);
        assert_eq!(votes_needed(5), 3);
        assert!(parse_cluster("a=u,b=u2,c=u3,d=u4,e=u5", "a", 1).is_err());
        assert!(parse_cluster("a=u,b=u2,c=u3,d=u4,e=u5", "a", 2).is_ok());
    }

    #[test]
    fn votes_are_granted_once_per_epoch_and_never_to_stale_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let failover = Failover::new(
            parse_cluster("a=u,b=u2,c=u3", "a", 1).unwrap(),
            "a".into(),
            EpochStore::open(directory.path()).unwrap(),
            false,
            Duration::from_secs(3),
            Duration::from_secs(5),
        );
        // Stale candidate: its log is behind the voter's.
        assert!(!failover.consider_vote(1, 5, 10).unwrap());
        // Same epoch, caught-up candidate — but epoch 1 was consumed? No:
        // a refused vote must not burn the epoch.
        assert!(failover.consider_vote(1, 10, 10).unwrap());
        // Second grant in the same epoch: refused, durably.
        assert!(!failover.consider_vote(1, 99, 10).unwrap());
        // Higher epoch: grantable again.
        assert!(failover.consider_vote(2, 10, 10).unwrap());
    }

    #[test]
    fn a_primary_that_sees_a_higher_epoch_is_deposed() {
        let directory = tempfile::tempdir().unwrap();
        let failover = Failover::new(
            parse_cluster("a=u,b=u2,c=u3", "a", 1).unwrap(),
            "a".into(),
            EpochStore::open(directory.path()).unwrap(),
            true,
            Duration::from_secs(3),
            Duration::from_secs(5),
        );
        assert_eq!(failover.role(), Role::Primary);
        failover.observe_epoch(7).unwrap();
        assert_eq!(failover.role(), Role::Deposed);
        // Deposition is permanent for this process: promote() cannot undo it.
        failover.promote();
        assert_eq!(failover.role(), Role::Deposed);
    }
}
