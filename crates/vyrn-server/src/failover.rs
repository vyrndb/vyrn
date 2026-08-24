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
use vyrn_log::{log_info, log_warn};

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

/// What this node currently is.
///
/// A primary that loses its lease or sees a higher epoch DEMOTES to
/// follower rather than fencing permanently — permanence deadlocks the
/// cluster: an ex-primary holding a durable-but-unacknowledged tail refuses
/// every vote for a candidate without it (the LSN rule), and if it may
/// never stand itself, no majority can form. As a follower it campaigns
/// with that longer log, wins, and the tail is delivered late — which an
/// unacknowledged write is always allowed to be. Writes are refused in any
/// non-primary role, so demotion fences exactly as hard as deposition did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Follower,
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
    /// Whether this primary has held a quorum since it (last) became one.
    /// The lease only fences a primary that HAS led: a freshly elected
    /// leader must survive its followers' reconnect rotation finding it.
    led_with_quorum: AtomicBool,
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
            led_with_quorum: AtomicBool::new(false),
            last_heard: Mutex::new(Instant::now()),
            lease,
            election_timeout,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Acquire)
    }

    pub fn role(&self) -> Role {
        *self
            .role
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn quorum_held(&self) {
        self.led_with_quorum.store(true, Ordering::Release);
        self.heard_from_leader();
    }

    pub fn has_led_with_quorum(&self) -> bool {
        self.led_with_quorum.load(Ordering::Acquire)
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
        self.demote_if_primary();
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
            // Granting resets this member's own election timer: the candidate
            // needs a full timeout to win and start streaming before its own
            // voters depose it with candidacies of their own.
            self.heard_from_leader();
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

    /// The candidate won: this node leads at `epoch`, its lease dormant
    /// until a quorum has actually connected.
    pub fn promote(&self) {
        let mut role = self
            .role
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *role = Role::Primary;
        self.led_with_quorum.store(false, Ordering::Release);
        self.heard_from_leader();
    }

    fn demote_if_primary(&self) {
        let mut role = self
            .role
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *role == Role::Primary {
            *role = Role::Follower;
            self.led_with_quorum.store(false, Ordering::Release);
        }
        drop(role);
        // A fresh follower timer: it campaigns only after a full timeout.
        self.heard_from_leader();
    }

    /// A primary that held a quorum and then lost it for a full lease
    /// demotes: its acknowledgements would promise a durability it cannot
    /// deliver, and an election it cannot see may already have replaced it.
    /// It remains a voter and a possible candidate — see [`Role`].
    pub fn step_down(&self) {
        self.demote_if_primary();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_shapes_the_safety_argument_rejects_are_refused() {
        assert!(parse_cluster("a=u,b=u2", "a", 1).is_err(), "2 members");
        assert!(
            parse_cluster("a=u,b=u2,c=u3", "a", 0).is_err(),
            "min-acks 0"
        );
        assert!(
            parse_cluster("a=u,b=u2,c=u3", "d", 1).is_err(),
            "self absent"
        );
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
    fn a_primary_that_sees_a_higher_epoch_demotes_and_may_campaign_again() {
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
        assert_eq!(
            failover.role(),
            Role::Follower,
            "a higher epoch demotes: someone won an election this node did not stand in"
        );
        assert_eq!(failover.epoch(), 7);
        /* Demotion, not permanent deposition: an ex-primary with a
         * durable-but-unacknowledged tail must be able to win a later
         * election, or the LSN vote rule deadlocks the cluster around the
         * very records nobody was promised. */
        let epoch = failover.stand().unwrap();
        assert_eq!(epoch, 8);
        failover.promote();
        assert_eq!(failover.role(), Role::Primary);
    }
}

/// Credentials a follower dials peers with when it stands for election —
/// the same replica credentials it streams with. The initial primary has
/// none and never stands: it leads until deposed, and rejoins after an
/// operator restarts it as a replica.
#[derive(Clone)]
pub struct PeerCredentials {
    pub password: String,
    pub ca_file: Option<std::path::PathBuf>,
    pub allow_plaintext: bool,
}

/// How often the timers are checked. Small against the lease and election
/// timeouts, so their configured values are what an operator reasons about.
const TICK: Duration = Duration::from_millis(250);
/// How long one vote solicitation may take before the peer is counted as
/// unreachable for this candidacy.
const VOTE_TIMEOUT: Duration = Duration::from_secs(2);

/// Drives the failover timers until the process exits.
///
/// On a primary: the lease. Holding a quorum of connected replica streams
/// renews it; a full lease without one self-fences (`step_down`) — the
/// acknowledgements this node could give would promise a durability it
/// cannot deliver, and an election it cannot see may already have replaced
/// it. On a follower: elections. A full election timeout (jittered per
/// member so two followers do not stand in the same instant) without a
/// frame from a live primary starts a candidacy.
pub async fn run_coordinator(
    failover: std::sync::Arc<Failover>,
    replication: std::sync::Arc<crate::replication::Replication>,
    engine: std::sync::Arc<std::sync::RwLock<vyrn_core::Engine>>,
    credentials: Option<PeerCredentials>,
) {
    // Deterministic per-member jitter: names differ, so timeouts differ.
    // Scrambled, not just folded: adjacent names ("b", "c") fold to adjacent
    // values, and near-equal jitter is exactly what makes two followers stand
    // in the same tick and split every election.
    let folded = failover.self_name.bytes().fold(0u64, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(byte as u64)
    });
    let jitter = Duration::from_millis((folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) % 1_500);
    loop {
        tokio::time::sleep(TICK).await;
        match failover.role() {
            Role::Primary => {
                let acks_needed = replication.min_acks();
                if replication.connected() >= acks_needed {
                    failover.quorum_held();
                } else if failover.has_led_with_quorum() && failover.silence() > failover.lease {
                    log_warn!(
                        "vyrnd.failover",
                        "quorum lost for a full lease; demoting to follower",
                        epoch = failover.epoch(),
                        connected = replication.connected(),
                        needed = acks_needed
                    );
                    failover.step_down();
                }
            }
            Role::Follower => {
                let Some(credentials) = credentials.as_ref() else {
                    continue;
                };
                if failover.silence() <= failover.election_timeout + jitter {
                    continue;
                }
                match stand_for_election(&failover, &engine, credentials).await {
                    Ok(true) => {
                        log_info!(
                            "vyrnd.failover",
                            "elected primary",
                            epoch = failover.epoch()
                        );
                        failover.promote();
                    }
                    Ok(false) => {
                        // Lost or short of quorum: reset the timer so the next
                        // candidacy waits a full jittered timeout instead of
                        // re-standing every tick.
                        failover.heard_from_leader();
                    }
                    Err(error) => {
                        log_warn!(
                            "vyrnd.failover",
                            "candidacy failed",
                            detail = format!("{error:#}")
                        );
                        failover.heard_from_leader();
                    }
                }
            }
        }
    }
}

/// One candidacy: persist the new epoch, solicit every other member, count.
async fn stand_for_election(
    failover: &Failover,
    engine: &std::sync::RwLock<vyrn_core::Engine>,
    credentials: &PeerCredentials,
) -> Result<bool> {
    use futures_util::{SinkExt, StreamExt};
    let epoch = failover.stand()?;
    let durable_lsn = engine.read().map(|engine| engine.last_lsn()).unwrap_or(0);
    log_info!(
        "vyrnd.failover",
        "standing for election",
        epoch = epoch,
        durable_lsn = durable_lsn
    );
    let mut votes = 1usize; // this member's own, persisted by stand()
    for member in &failover.members {
        if member.name == failover.self_name {
            continue;
        }
        let solicit = async {
            let (mut framed, _) = crate::replica::connect_authenticated(
                &member.url,
                &credentials.password,
                credentials.ca_file.as_deref(),
                credentials.allow_plaintext,
            )
            .await?;
            framed
                .send(vyrn_protocol::Envelope::new(
                    1,
                    vyrn_protocol::Message::VoteRequest { epoch, durable_lsn },
                ))
                .await?;
            match framed.next().await {
                Some(Ok(envelope)) => match envelope.message {
                    vyrn_protocol::Message::VoteResponse { granted, epoch } => {
                        Ok::<(bool, u64), anyhow::Error>((granted, epoch))
                    }
                    other => bail!("unexpected reply to a vote request: {other:?}"),
                },
                Some(Err(error)) => Err(error.into()),
                None => bail!("peer closed the connection during the vote"),
            }
        };
        // Unreachable or failing peers simply do not vote; that is what
        // makes a minority partition unable to elect.
        if let Ok(Ok((granted, peer_epoch))) = tokio::time::timeout(VOTE_TIMEOUT, solicit).await {
            if peer_epoch > epoch {
                // Someone leads (or stands) at a higher epoch; this
                // candidacy is already history. Adopt and yield.
                failover.observe_epoch(peer_epoch)?;
                return Ok(false);
            }
            if granted {
                votes += 1;
            }
        }
        if votes >= votes_needed(failover.members.len()) {
            return Ok(true);
        }
    }
    Ok(votes >= votes_needed(failover.members.len()))
}
