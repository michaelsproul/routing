use chain::block::{BlockId, Block};
use id::PublicId;
use rust_sodium::crypto::sign::Signature;
use std::collections::BTreeMap;

// Map from (block_id -> (block_id -> vote_signatures)).
type VoteMap = BTreeMap<BlockId, BTreeMap<BlockId, BTreeMap<PublicId, Signature>>>;

/// Storage for `Vote` structs that provides easy look-up and exploration functionality.
// TODO(chain): replace by an on-disk database with quick look-up by `from` AND `to`.
pub struct VoteStore {
    votes: VoteMap,
    rev_votes: VoteMap,
}

impl VoteStore {
    pub fn new() -> Self {
        VoteStore {
            votes: VoteMap::new(),
            rev_votes: VoteMap::new()
        }
    }
}
