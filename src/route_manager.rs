// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use SortedVec;
use crust::{PeerId, PrivConnectionInfo, PubConnectionInfo};
use error::RoutingError;
use id::PublicId;
use member_log::{LogId, MemberChange, MemberEntry, MemberLog, MemberLogError};
use peer_manager::PeerManager;
use resource_proof::ResourceProof;
use routing_table::{Authority, OtherMergeDetails, OwnMergeDetails, OwnMergeState, Prefix,
                    RemovalDetails, RoutingTable};
use routing_table::Error as RoutingTableError;
use signature_accumulator::ACCUMULATION_TIMEOUT_SECS;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::mem;
use std::time::{Duration, Instant};
use xor_name::XorName;

/// Time (in seconds) between accepting a new candidate (i.e. receiving an `AcceptAsCandidate` from
/// our section) and sending a `CandidateApproval` for this candidate.  If the candidate cannot
/// satisfy the proof of resource challenge within this time, no `CandidateApproval` is sent.
pub const RESOURCE_PROOF_DURATION_SECS: u64 = 300;
/// Time (in seconds) after which a `VotedFor` candidate will be removed.
const CANDIDATE_ACCEPT_TIMEOUT_SECS: u64 = 60;
/// Time (in seconds) the node waits for connection from an expected node.
const NODE_CONNECT_TIMEOUT_SECS: u64 = 60;

pub type SectionMap = BTreeMap<Prefix<XorName>, BTreeSet<PublicId>>;

#[derive(Debug)]
enum CandidateState {
    VotedFor,
    AcceptedAsCandidate,
    Approved,
}

#[derive(Debug)]
struct ChallengeResponse {
    target_size: usize,
    difficulty: u8,
    seed: Vec<u8>,
    proof: VecDeque<u8>,
}

/// Holds the information of the joining node.
#[derive(Debug)]
struct Candidate {
    insertion_time: Instant,
    challenge_response: Option<ChallengeResponse>,
    client_auth: Authority<XorName>,
    state: CandidateState,
    passed_our_challenge: bool,
}

impl Candidate {
    fn new(client_auth: Authority<XorName>) -> Candidate {
        Candidate {
            insertion_time: Instant::now(),
            challenge_response: None,
            client_auth: client_auth,
            state: CandidateState::VotedFor,
            passed_our_challenge: false,
        }
    }

    fn is_expired(&self) -> bool {
        let timeout_duration = match self.state {
            CandidateState::VotedFor => Duration::from_secs(CANDIDATE_ACCEPT_TIMEOUT_SECS),
            CandidateState::AcceptedAsCandidate |
            CandidateState::Approved => {
                Duration::from_secs(RESOURCE_PROOF_DURATION_SECS + ACCUMULATION_TIMEOUT_SECS)
            }
        };
        self.insertion_time.elapsed() > timeout_duration
    }

    fn is_approved(&self) -> bool {
        match self.state {
            CandidateState::VotedFor |
            CandidateState::AcceptedAsCandidate => false,
            CandidateState::Approved => true,
        }
    }
}

/// Route manager
#[derive(Debug)]
pub struct RouteManager {
    /// Joining nodes which want to join our section
    candidates: HashMap<XorName, Candidate>,
    /// Peers we expect to connect to
    expected_peers: HashMap<XorName, Instant>,
    // Log of routing table changes
    pub log: MemberLog,
}

impl RouteManager {
    /// Returns a new route manager.
    pub fn new(log: MemberLog) -> RouteManager {
        RouteManager {
            candidates: HashMap::new(),
            expected_peers: HashMap::new(),
            log: log,
        }
    }

    /// Notes that a new peer should be expected. This should only be called for peers not already
    /// in our routing table.
    pub fn expect_peer(&mut self, id: &PublicId) {
        let _ = self.expected_peers.insert(*id.name(), Instant::now());
    }

    /// Are we expecting a connection from this name?
    pub fn is_expected(&self, name: &XorName) -> bool {
        self.expected_peers.contains_key(name)
    }

    /// Clears the routing table and resets this node's public ID.
    pub fn relocate(&mut self,
                    our_public_id: PublicId,
                    log_start_point: LogId,
                    section_members: SortedVec<PublicId>) {
        self.log.relocate(our_public_id, log_start_point, section_members)
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        self.log.table()
    }

    /// Add prefixes into routing table.
    pub fn add_prefixes(&mut self, prefixes: Vec<Prefix<XorName>>) -> Result<(), RoutingError> {
        Ok(self.log.table_mut().add_prefixes(prefixes)?)
    }

    /// Adds a potential candidate to the candidate list setting its state to `VotedFor`.  If
    /// another ongoing (i.e. unapproved) candidate exists, or if the candidate is unsuitable for
    /// adding to our section, returns an error.
    pub fn expect_candidate(&mut self,
                            candidate_name: XorName,
                            client_auth: Authority<XorName>)
                            -> Result<(), RoutingError> {
        if let Some((ongoing_name, _)) =
            self.candidates.iter().find(|&(_, candidate)| !candidate.is_approved()) {
            trace!("{:?} Rejected {} as a new candidate: still handling attempt by {}.",
                   self,
                   candidate_name,
                   ongoing_name);
            return Err(RoutingError::AlreadyHandlingJoinRequest);
        }
        self.log.table().should_join_our_section(&candidate_name)?;
        let _ = self.candidates.insert(candidate_name, Candidate::new(client_auth));
        Ok(())
    }

    /// Our section has agreed that the candidate should be accepted pending proof of resource.
    /// Replaces any other potential candidate we have previously voted for.  Sets the candidate
    /// state to `AcceptedAsCandidate`.
    ///
    /// Returns the identifier for the last log entry and the member list for our section at this
    /// time.
    pub fn accept_as_candidate(&mut self,
                               peer_mgr: &PeerManager,
                               candidate_name: XorName,
                               client_auth: Authority<XorName>)
                               -> Result<(LogId, SortedVec<PublicId>), RoutingError> {
        self.remove_unapproved_candidates(&candidate_name);
        self.candidates
            .entry(candidate_name)
            .or_insert_with(|| Candidate::new(client_auth))
            .state = CandidateState::AcceptedAsCandidate;
        let log_id = self.log.last_id().ok_or(MemberLogError::InvalidState)?;
        let our_section = self.log.table().our_section();
        // TODO: we may need a new log entry here; we should get the section list from the log once
        // it's the definitive source.)
        Ok((log_id, peer_mgr.get_pub_ids(our_section, self.log.own_id()).into()))
    }

    /// Verifies proof of resource.  If the response is not the current candidate, or if it fails
    /// validation, returns `Err`.  Otherwise returns the target size, difficulty and the time
    /// elapsed since the candidate was inserted.
    pub fn verify_candidate(&mut self,
                            candidate_name: &XorName,
                            part_index: usize,
                            part_count: usize,
                            proof_part: Vec<u8>,
                            leading_zero_bytes: u64)
                            -> Result<Option<(usize, u8, Duration)>, RoutingError> {
        let candidate = if let Some(candidate) = self.candidates.get_mut(candidate_name) {
            candidate
        } else {
            return Err(RoutingError::UnknownCandidate);
        };
        let challenge_response = &mut (if let Some(ref mut rp) = candidate.challenge_response {
            rp
        } else {
            return Err(RoutingError::FailedResourceProofValidation);
        });
        challenge_response.proof.extend(proof_part);
        if part_index + 1 != part_count {
            return Ok(None);
        }
        let rp_object = ResourceProof::new(challenge_response.target_size,
                                           challenge_response.difficulty);
        if rp_object.validate_all(&challenge_response.seed,
                                  &challenge_response.proof,
                                  leading_zero_bytes) {
            candidate.passed_our_challenge = true;
            Ok(Some((challenge_response.target_size,
                     challenge_response.difficulty,
                     candidate.insertion_time.elapsed())))
        } else {
            Err(RoutingError::FailedResourceProofValidation)
        }
    }

    /// Returns a tuple containing the verified candidate's `PublicId`, its client `Authority` and
    /// the `PublicId`s of all routing table entries.
    pub fn verified_candidate_info
        (&self,
         peer_mgr: &PeerManager)
         -> Result<(PublicId, Authority<XorName>, SectionMap), RoutingError> {
        if let Some((name, candidate)) =
            self.candidates
                .iter()
                .find(|&(_, cand)| cand.passed_our_challenge && !cand.is_approved()) {
            return if let Some(pub_id) = peer_mgr.get_pub_id(name) {
                Ok((*pub_id, candidate.client_auth, self.pub_ids_by_section()))
            } else {
                Err(RoutingError::UnknownCandidate)
            };
        }
        if let Some((name, _)) = self.candidates.iter().find(|&(_, cand)| !cand.is_approved()) {
            info!("{:?} Candidate {} has not passed our resource proof challenge in time. Not \
                   sending approval vote to our section with {:?}",
                  self,
                  name,
                  self.log.table().our_prefix());
        }
        Err(RoutingError::UnknownCandidate)
    }

    /// Handles accumulated candidate approval.  Marks the candidate as `Approved` and returns the
    /// candidate's `PeerId`; or `Err` if the peer is not the candidate or we are missing its info.
    pub fn handle_candidate_approval(&mut self,
                                     peer_mgr: &PeerManager,
                                     candidate_name: XorName,
                                     client_auth: Authority<XorName>)
                                     -> Result<PeerId, RoutingError> {
        if let Some(candidate) = self.candidates.get_mut(&candidate_name) {
            candidate.state = CandidateState::Approved;
            if let Some(peer_id) = peer_mgr.get_peer_id(&candidate_name) {
                return Ok(*peer_id);
            } else {
                trace!("Node({:?}) No peer with name {:?}",
                       self.log.table().our_name(),
                       candidate_name);
            }
            return Err(RoutingError::InvalidStateForOperation);
        }

        self.remove_unapproved_candidates(&candidate_name);
        let mut candidate = Candidate::new(client_auth);
        candidate.state = CandidateState::Approved;
        let _ = self.candidates.insert(candidate_name, candidate);
        trace!("{:?} No candidate with name {:?}", self, candidate_name);
        // TODO: more specific return error
        Err(RoutingError::InvalidStateForOperation)
    }

    /// Updates peer's state to `Candidate` in the peer map if it is an unapproved candidate and
    /// returns the whether the candidate needs to perform the resource proof.
    ///
    /// Returns:
    ///
    /// * Ok(true)                      if the peer is an unapproved candidate
    /// * Ok(false)                     if the peer has already been approved
    /// * Err(CandidateIsTunnelling)    if the peer is tunnelling
    /// * Err(UnknownCandidate)         if the peer is not in the candidate list
    pub fn handle_candidate_identify(&mut self,
                                     peer_mgr: &PeerManager,
                                     pub_id: &PublicId,
                                     peer_id: &PeerId,
                                     target_size: usize,
                                     difficulty: u8,
                                     seed: Vec<u8>)
                                     -> Result<bool, RoutingError> {
        if let Some(candidate) = self.candidates.get_mut(pub_id.name()) {
            if candidate.is_approved() {
                Ok(false)
            } else {
                peer_mgr.set_to_candidate(pub_id, peer_id)?;
                candidate.challenge_response = Some(ChallengeResponse {
                    target_size: target_size,
                    difficulty: difficulty,
                    seed: seed,
                    proof: VecDeque::new(),
                });
                Ok(true)
            }
        } else {
            Err(RoutingError::UnknownCandidate)
        }
    }

    /// Logs info about ongoing candidate state, if any.
    pub fn show_candidate_status(&self) {
        let mut have_candidate = false;
        let log_prefix = format!("{:?} Candidate Status - ", self);
        for (name, candidate) in self.candidates.iter().filter(|&(_, cand)| !cand.is_expired()) {
            have_candidate = true;
            let mut log_msg = format!("{}{} ", log_prefix, name);
            match candidate.challenge_response {
                Some(ChallengeResponse { ref target_size, ref proof, .. }) => {
                    if candidate.passed_our_challenge {
                        log_msg = format!("{}has passed our challenge ", log_msg);
                    } else if proof.is_empty() {
                        log_msg = format!("{}hasn't responded to our challenge yet ", log_msg);
                    } else {
                        log_msg = format!("{}has sent {}% of resource proof ",
                                          log_msg,
                                          (proof.len() * 100) / target_size);
                    }
                    if candidate.is_approved() {
                        log_msg = format!("{}and is approved by our section.", log_msg);
                    } else {
                        log_msg = format!("{}and is not yet approved by our section.", log_msg);
                    }
                }
                None => {
                    log_msg = format!("{}has not sent CandidateIdentify yet.", log_msg);
                }
            }
            trace!("{}", log_msg);
        }

        if have_candidate {
            return;
        }

        trace!("{}No candidate is currently being handled.", log_prefix);
    }

    /// Removes the given peer, returning the removal details.
    pub fn remove_node(&mut self,
                       name: &XorName)
                       -> Result<RemovalDetails<XorName>, RoutingTableError> {
        self.log.table_mut().remove(name)
    }

    /// Tries to add the given peer to the routing table. If successful, this returns `Ok(true)` if
    /// the addition should cause our section to split or `Ok(false)` if the addition shouldn't
    /// cause a split.
    pub fn add_to_routing_table(&mut self,
                                pub_id: &PublicId,
                                peer_id: &PeerId)
                                -> Result<(), RoutingTableError> {
        let _ = self.expected_peers.remove(pub_id.name());
        self.log.table_mut().add(*pub_id.name())
    }

    /// Splits the indicated section and returns `(peers_to_drop, opt_prefix)`.
    ///
    /// `peers_to_drop` is a list of any peers to which we should not remain connected.
    ///
    /// `opt_prefix` is the new prefix for our section in the case we split our own section, or
    /// `None` in the case we split a different section.
    pub fn split_section(&mut self,
                         peer_mgr: &PeerManager,
                         prefix: Prefix<XorName>)
                         -> (Vec<(XorName, PeerId)>, Option<Prefix<XorName>>) {
        let (names_to_drop, our_new_prefix) = self.log.table_mut().split(prefix);
        let ids_to_drop = peer_mgr.drop_via_split(names_to_drop);

        let removal_keys = self.candidates
            .iter()
            .find(|&(name, candidate)| {
                !candidate.is_approved() && !self.log.table().our_prefix().matches(name)
            })
            .map(|(name, _)| *name);
        for name in removal_keys.iter() {
            let _ = self.candidates.remove(name);
            trace!("{:?} Removed unapproved candidate {:?} after split.",
                   self,
                   name);
        }

        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers.into_iter()
            .filter(|&(ref name, _)| self.log.table().need_to_add(name) == Ok(()))
            .collect();

        (ids_to_drop, our_new_prefix)
    }

    /// Adds the given prefix to the routing table, splitting or merging as necessary. Returns the
    /// list of peers that have been dropped and need to be disconnected.
    pub fn add_prefix(&mut self, prefix: Prefix<XorName>) -> Vec<(XorName, PeerId)> {
        // FIXME: do we still want this func?
        /*
        let names_to_drop = self.log.table_mut().add_prefix(prefix);
        let old_expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        self.expected_peers = old_expected_peers.into_iter()
            .filter(|&(ref name, _)| self.log.table().need_to_add(name) == Ok(()))
            .collect();
        names_to_drop.into_iter()
            .filter_map(|name| if let Some(peer_id) = peer_mgr.remove_by_name(&name) {
                (name, peer_id)
            } else {
                None
            })
            .collect()
        */
        vec![]
    }

    /// Wraps `RoutingTable::should_merge` with an extra check.
    ///
    /// Returns sender prefix, merge prefix, then sections.
    pub fn should_merge(&self, peer_mgr: &PeerManager) -> Option<(Prefix<XorName>, Prefix<XorName>, SectionMap)> {
        if !self.log.table().they_want_to_merge() && !self.expected_peers.is_empty() {
            return None;
        }
        self.log.table().should_merge().map(|merge_details| {
            let sections =
                merge_details.sections
                    .into_iter()
                    .map(|(prefix, members)| {
                        (prefix, peer_mgr.get_pub_ids(&members, self.log.own_id()).into_iter().collect())
                    })
                    .collect();
            (merge_details.sender_prefix, merge_details.merge_prefix, sections)
        })
    }

    // Returns the `OwnMergeState` from `RoutingTable` which defines what further action needs to be
    // taken by the node, and the list of peers to which we should now connect (only those within
    // the merging sections for now).
    pub fn merge_own_section(&mut self,
                             sender_prefix: Prefix<XorName>,
                             merge_prefix: Prefix<XorName>,
                             sections: SectionMap)
                             -> (OwnMergeState<XorName>, Vec<PublicId>) {
        self.remove_expired();
        let needed = sections.iter()
            .flat_map(|(_, pub_ids)| pub_ids)
            .filter(|pub_id| !self.log.table().has(pub_id.name()))
            .cloned()
            .collect();

        let sections_as_names = sections.into_iter()
            .map(|(prefix, members)| {
                (prefix, members.into_iter().map(|pub_id| *pub_id.name()).collect::<HashSet<_>>())
            })
            .collect();

        let own_merge_details = OwnMergeDetails {
            sender_prefix: sender_prefix,
            merge_prefix: merge_prefix,
            sections: sections_as_names,
        };
        let mut expected_peers = mem::replace(&mut self.expected_peers, HashMap::new());
        expected_peers.extend(own_merge_details.sections
            .values()
            .flat_map(|section| section.iter())
            .filter_map(|name| if self.log.table().has(name) {
                None
            } else {
                Some((*name, Instant::now()))
            }));
        self.expected_peers = expected_peers;
        (self.log.table_mut().merge_own_section(own_merge_details), needed)
    }

    pub fn merge_other_section(&mut self,
                               prefix: Prefix<XorName>,
                               section: BTreeSet<PublicId>)
                               -> HashSet<PublicId> {
        self.remove_expired();

        let merge_details = OtherMergeDetails {
            prefix: prefix,
            section: section.iter().map(|public_id| *public_id.name()).collect(),
        };
        let needed_names = self.log.table_mut().merge_other_section(merge_details);
        self.expected_peers.extend(needed_names.iter().map(|name| (*name, Instant::now())));
        section.into_iter().filter(|pub_id| needed_names.contains(pub_id.name())).collect()
    }

    // Handle. If this is a valid new entry, return a reference to it (in the log).
    pub fn handle_log_entry(&mut self, entry: MemberEntry) -> Option<&MemberEntry> {
        self.log.append(entry)
    }

    // Removes all candidates except those which are approved or have the given name
    fn remove_unapproved_candidates(&mut self, candidate_name: &XorName) {
        let old_candidates = mem::replace(&mut self.candidates, HashMap::new());
        self.candidates = old_candidates.into_iter()
            .filter(|&(name, ref candidate)| name == *candidate_name || candidate.is_approved())
            .collect();
    }

    /// Removes expired candidates and returns the list of peers from which we should disconnect.
    pub fn remove_expired_candidates(&mut self) -> Vec<PeerId> {
        let candidates = mem::replace(&mut self.candidates, HashMap::new());
        let (to_prune, to_keep) = candidates.into_iter()
            .partition(|&(_, ref candidate)| candidate.is_expired());
        self.candidates = to_keep;
        to_prune.into_iter().filter_map(|(name, _)| self.get_peer_id(&name).cloned()).collect()
    }

    /// Returns the public IDs of all routing table entries, sorted by section.
    pub fn pub_ids_by_section(&self, peer_mgr: &PeerManager) -> SectionMap {
        self.log
            .table()
            .all_sections()
            .into_iter()
            .map(|(prefix, names)| (prefix, peer_mgr.get_pub_ids(&names, self.log.own_id())))
            .collect()
    }

    // TODO: this should get from the log itself when that is up to date
    fn get_current_members(&self, peer_mgr: &PeerManager) -> SortedVec<PublicId> {
        self.log
            .table()
            .our_section()
            .iter()
            .filter_map(|name| if name == self.log.own_id().name() {
                Some(*self.log.own_id())
            } else if let Some(pub_id) = peer_mgr.get_pub_id(name) {
                Some(*pub_id)
            } else {
                error!("{:?} Missing public ID for peer {:?}.", self, name);
                None
            })
            .collect()
    }

    /// Make a log entry to split
    pub fn make_split_entry(&self) -> Result<MemberEntry, RoutingError> {
        let change = MemberChange::SectionSplit {
            prev_id: self.log.last_id().ok_or(MemberLogError::InvalidState)?,
        };
        Ok(MemberEntry::new(self.get_current_members(), change))
    }

    /// Removes timed out expected peers (those we tried to connect to).
    pub fn remove_expired_expected(&mut self) {
        let mut expired_expected = Vec::new();
        for (name, timestamp) in &self.expected_peers {
            if timestamp.elapsed() >= Duration::from_secs(NODE_CONNECT_TIMEOUT_SECS) {
                expired_expected.push(*name);
            }
        }
        for name in expired_expected {
            let _ = self.expected_peers.remove(&name);
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl RouteManager {
    /// Removes all peers that are not connected, as well as all expected peers and candidates.
    /// Returns `true` if any entry was removed, and `false` if there were no such peers.
    pub fn remove_connecting_peers(&mut self, peer_mgr: &mut PeerManager) -> bool {
        let had_connecting = peer_mgr.remove_connecting_peers();

        if !had_connecting && self.expected_peers.is_empty() && self.candidates.is_empty() {
            return false;
        }

        self.expected_peers.clear();
        self.candidates.clear();
        true
    }
}
