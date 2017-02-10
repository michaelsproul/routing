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

use maidsafe_utilities::serialisation::{SerialisationError, serialise};
use routing_table::RoutingTable;
use rust_sodium::crypto::hash::sha256;
use std::result;
use xor_name::XorName;

/// We use this to identify log entries.
//TODO: why are we using SHA256?
pub type Digest = sha256::Digest;

/// Internal result type
pub type Result<T> = result::Result<T, MemberLogError>;

/// What happened in a change
#[derive(Clone, RustcEncodable, RustcDecodable)]
pub enum MemberChange {
    /// The node starting a network
    InitialNode(XorName),
}

/// Entry recording a membership change
//TODO: add PublicId of each node?
//TODO: add checksum of table after changes?
#[derive(Clone, RustcEncodable, RustcDecodable)]
pub struct MemberEntry {
    // Identifier of this change, applied over the previous change
    id: Digest,
    // identifier of previous change
    prev_id: Digest,
    // Change itself
    change: MemberChange,
}

impl MemberEntry {
    /// Create a new entry, given the identifier of the previous entry, a checksum, and a change.
    pub fn new(prev_id: Digest, change: MemberChange) -> Result<Self> {
        // Append all entries into a buffer and create a hash of that.
        // TODO: for security, the hash may want to include more details (e.g. full routing table)?
        let mut buf = vec![];
        buf.extend_from_slice(prev_id.as_ref());
        // TODO: why does serialise return a Result??
        buf.extend_from_slice(&serialise(&change)?);

        Ok(MemberEntry {
            id: sha256::hash(&buf),
            prev_id: prev_id,
            change: change,
        })
    }
}

/// Log of section membership changes
#[derive(Clone)]
pub struct MemberLog {
    log: Vec<MemberEntry>,
    table: RoutingTable<XorName>,
}

impl MemberLog {
    /// Create a new, empty log, with a valid routing table.
    ///
    /// The log is invalid until an initial entry has been inserted (see `insert_initial()`).
    pub fn new(node_name: XorName, min_section_size: usize) -> Self {
        MemberLog {
            log: vec![],
            table: RoutingTable::<XorName>::new(node_name, min_section_size),
        }
    }

    /// Add an initial entry to the log (only the first node in the network should do this).
    pub fn insert_initial(&mut self) -> Result<()> {
        if !self.log.is_empty() {
            return Err(MemberLogError::InvalidState);
        }

        // Use 0 as the initial hash / identifier.
        let initial_hash = Digest::from_slice(&[0u8; 32]).ok_or(MemberLogError::Digest)?;
        let node_name = *self.table.our_name();
        let change = MemberChange::InitialNode(node_name);
        // Initial name sum is just first name:
        let entry = MemberEntry::new(initial_hash, change)?;
        self.log.push(entry);
        Ok(())
    }

    /// Try to append an entry to the log
    //TODO: use
    #[allow(unused)]
    pub fn append(&mut self, entry: MemberEntry) -> Result<()> {
        if self.log.last().ok_or(MemberLogError::InvalidState)?.id != entry.prev_id {
            // Refuse to apply if hash doesn't match
            return Err(MemberLogError::PrevIdMismatch);
        }

        match &entry.change {
            &MemberChange::InitialNode(_) => return Err(MemberLogError::CannotAppendInitialEntry),
        }

        // TODO: check table checksum. (But we can't do any more than warn about errors?)
        self.log.push(entry);
        Ok(())
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

    /// Set a new table.
    /// TODO: revise how this happens.
    pub fn set_table(&mut self, table: RoutingTable<XorName>) {
        self.table = table;
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
