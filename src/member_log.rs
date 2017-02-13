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

#![cfg_attr(rustfmt, rustfmt_skip)]

use id::PublicId;
use maidsafe_utilities::serialisation::{SerialisationError, serialise};
use routing_table::RoutingTable;
use rust_sodium::crypto::hash::sha256;
use std::fmt;
use std::result;
use xor_name::XorName;

/// We use this to identify log entries.
//TODO: why are we using SHA256?
pub type Digest = sha256::Digest;

/// Internal result type
pub type Result<T> = result::Result<T, MemberLogError>;

/// What happened in a change
#[derive(Clone, Debug, RustcEncodable, RustcDecodable)]
pub enum MemberChange {
    /// The node starting a network
    InitialNode(XorName),
    /*
    NodeAdded {
        prev_hash: Digest,
        new_name: XorName,
    },
    NodeLost {
        prev_hash: Digest,
        lost_name: XorName,
    },
    SectionSplit {
        prev_hash: Digest,
    },
    SectionMerge {
        /// Hash of previous block for lexicographically lesser section (P0).
        left_hash: Digest,
        /// Hash of previous block for lexicographically greater section (P1).
        right_hash: Digest,
    }
    */
}

/// Entry recording a membership change
// TODO: maybe delete this entirely in favour of just using MemberChange, the id is computable
// from the change field (and doesn't need to be stored).
#[derive(Clone, Debug, RustcEncodable, RustcDecodable)]
pub struct MemberEntry {
    // Identifier of this change, applied over the previous change
    id: Digest,
    // List of members after applying this change, sorted by name.
    // TODO: do we want to list all PublicIds in each entry?
    members: Vec<PublicId>,
    // Change itself
    change: MemberChange,
}

impl MemberEntry {
    /// Create a new entry, given the members of the section after a change, and the change itself.
    ///
    /// The list of members is sorted in this method.
    pub fn new(mut members: Vec<PublicId>, change: MemberChange) -> Result<Self> {
        members.sort_by_key(|id| *id.name());

        // Append all entries into a buffer and create a hash of that.
        // TODO: for security, the hash may want to include more details (e.g. full routing table)?
        let mut buf = vec![];
        // TODO: why does serialise return a Result??
        buf.extend_from_slice(&serialise(&members)?);
        buf.extend_from_slice(&serialise(&change)?);

        Ok(MemberEntry {
            id: sha256::hash(&buf),
            members: members,
            change: change,
        })
    }

    // TODO: maybe return a Result<(), SomeError>
    // TODO: remove allow(unused)
    #[allow(unused)]
    fn is_successor_of(&self, prev_entry: &MemberEntry) -> bool {
        use self::MemberChange::*;

        // Check hash.
        match self.change {
            /*
            NodeAdded { prev_hash, .. } |
            NodeLost { prev_hash, .. } |
            SectionSplit { prev_hash, .. } => {
                if prev_hash != prev_entry.id {
                    return false;
                }
            }
            SectionMerge { left_hash, right_hash, .. } => {
                let prev_hash = prev_entry.id;
                if left_hash != prev_hash && right_hash != prev_hash {
                    return false;
                }
            }
            */
            InitialNode(..) => return false,
        }

        // TODO: check signatures
        true
    }
}

/// Log of section membership changes
#[derive(Clone)]
pub struct MemberLog {
    own_id: PublicId,
    log: Vec<MemberEntry>,
    table: RoutingTable<XorName>,
}

impl MemberLog {
    /// Create a new log as the first node (i.e. state in the log that this is the initial node in
    /// the network).
    pub fn new_first(our_id: PublicId, min_section_size: usize) -> Result<Self> {
        let change = MemberChange::InitialNode(*our_id.name());
        let entry = MemberEntry::new(vec![our_id.clone()], change)?;
        let table = RoutingTable::new(*our_id.name(), min_section_size);
        Ok(MemberLog { log: vec![entry], own_id: our_id, table: table })
    }

    /// Create a new, empty log, with a valid routing table.
    ///
    /// The log is invalid until an entry has been inserted.
    pub fn new_empty(our_id: PublicId, min_section_size: usize) -> Self {
        let table = RoutingTable::new(*our_id.name(), min_section_size);
        MemberLog { log: vec![], own_id: our_id, table: table }
    }

    /// Node has relocated: clear the log and table, and change our id.
    pub fn relocate(&mut self, our_id: PublicId) {
        if !self.log.is_empty() {
            warn!("{:?} Reset to {:?} from non-empty log.", self, our_id.name());
        }

        let min_section_size = self.table().min_section_size();
        self.table = RoutingTable::new(*our_id.name(), min_section_size);
        self.own_id = our_id;
        self.log = vec![]; //TODO: should we set log at the same time?
    }

    /// Try to append an entry to the log
    //TODO: use
    #[allow(unused)]
    pub fn append(&mut self, block: MemberEntry) -> Result<()> {
        if !block.is_successor_of(self.log.last().ok_or(MemberLogError::InvalidState)?) {
            // Refuse to apply if hash doesn't match
            return Err(MemberLogError::PrevIdMismatch);
        }

        // TODO: check table checksum. (But we can't do any more than warn about errors?)
        self.log.push(block);
        Ok(())
    }

    /// Get our public identifier
    pub fn own_id(&self) -> &PublicId {
        &self.own_id
    }

    /// Get read access to the routing table
    pub fn table(&self) -> &RoutingTable<XorName> {
        &self.table
    }

    /// Get write access to the routing table.
    /// TODO: eventually all changes should be handled internally and this can go away!
    pub fn table_mut(&mut self) -> &mut RoutingTable<XorName> {
        &mut self.table
    }
}

impl fmt::Debug for MemberLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Member log of {:?}:", self.own_id)?;
        writeln!(f, "\tTable: {:?}", self.table)?;
        if self.log.len() <= 3 {
            write!(f, "\tLog: {:?}", self.log)
        } else {
            let ll = self.log.len();
            write!(f,
                   "\tLog: [{:?}, <omitted {} entries>, {:?}, {:?}]",
                   self.log[0],
                   ll - 3,
                   self.log[ll - 2],
                   self.log[ll - 1])
        }
    }
}

#[derive(Debug)]
//TODO: for some reason values used in unused methods aren't counted.
#[allow(unused)]
pub enum MemberLogError {
    CannotAppendInitialEntry,
    Digest,
    InvalidState,
    PrevIdMismatch,
    Serialisation(SerialisationError),
}

impl From<SerialisationError> for MemberLogError {
    fn from(e: SerialisationError) -> Self {
        MemberLogError::Serialisation(e)
    }
}
