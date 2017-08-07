use id::PublicId;
use routing_table::Prefix;
use sha3;
use std::collections::{BTreeSet, BTreeMap};
use tiny_keccak::sha3_256;
use xor_name::XorName;
use maidsafe_utilities::serialisation::serialise;
use rust_sodium::crypto::sign::Signature;
use {QUORUM_NUMERATOR, QUORUM_DENOMINATOR};
use chain::block_store::BlockStore;

/// The state of a section at a single point in time.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Block {
    prefix: Prefix<XorName>,
    version: u64,
    members: BTreeSet<PublicId>,
}

/// The hash of a `Block`, which is used to identify it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockId(pub sha3::Digest256);

/// A vote that the given `to` block is a successor of the given `from` block.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub from: BlockId,
    pub to: BlockId,
}

/// A vote with accompanying signatures.
pub struct SignedVote {
    vote: Vote,
    signatures: BTreeMap<PublicId, Signature>,
}

impl Block {
    /// Create a genesis block.
    pub fn genesis(first_node: PublicId) -> Self {
        Block {
            prefix: Prefix::default(),
            version: 0,
            members: btreeset!{first_node},
        }
    }

    /// Create a new block with a node added.
    pub fn add_node(&self, added: PublicId) -> Self {
        let mut members = self.members.clone();
        members.insert(added);
        Block {
            prefix: self.prefix,
            version: self.version + 1,
            members,
        }
    }

    /// Create a new block with a node removed.
    pub fn remove_node(&self, removed: &PublicId) -> Self {
        let mut members = self.members.clone();
        members.remove(removed);
        Block {
            prefix: self.prefix,
            version: self.version + 1,
            members,
        }
    }

    /// Hash this block to determine its `BlockId`.
    pub fn get_id(&self) -> BlockId {
        let serialised = unwrap!(serialise(self), "Failed to serialise block");
        BlockId(sha3_256(&serialised))
    }

    /// Is this block admissible after the given other block?
    pub fn is_admissible_after(&self, other: &Block) -> bool {
        if self.version <= other.version {
            return false;
        }

        // Add/remove case.
        if self.prefix == other.prefix {
            self.members.symmetric_difference(&other.members).count() == 1
        }
        // Split case.
        else if self.prefix.popped() == other.prefix {
            let filtered = other.members.iter().filter(
                |id| self.prefix.matches(id.name()),
            );
            self.members.iter().eq(filtered)
        }
        // Merge case
        else if other.prefix.popped() == self.prefix {
            let filtered = self.members.iter().filter(
                |id| other.prefix.matches(id.name()),
            );
            other.members.iter().eq(filtered)
        } else {
            false
        }
    }

    /// Returns `true` if `other` should be removed from the current blocks when `self` is a
    /// current candidate.
    pub fn outranks(&self, other: &Block) -> bool {
        if self.prefix == other.prefix {
            if self.members.len() != other.members.len() {
                self.members.len() > other.members.len()
            } else {
                self.members > other.members
            }
        } else {
            self.prefix.is_compatible(&other.prefix) &&
                self.prefix.bit_count() < other.prefix.bit_count()
        }
    }

    /// Does this block contain sufficient members to split into two sections of `min_split_size`?
    pub fn should_split(&self, min_split_size: usize) -> bool {
        let p0 = self.prefix.pushed(false);
        let mut len0 = 0;
        let mut len1 = 0;
        for id in &self.members {
            if p0.matches(id.name()) {
                len0 += 1;
            } else {
                len1 += 1;
            }
        }
        len0 >= min_split_size && len1 >= min_split_size
    }
}

impl BlockId {
    pub fn into_block<'a>(&self, blocks: &'a BlockStore) -> &'a Block {
        // FIXME(michael): decide on a way to deal with block IDs for which we lack the block
        unwrap!(blocks.get(self))
    }
}

impl Vote {
    pub fn is_witnessing(&self, blocks: &BlockStore) -> bool {
        !self.to.into_block(blocks).is_admissible_after(
            self.from.into_block(blocks),
        )
    }

    // TODO(chain): check signatures?
    pub fn is_quorum(&self, blocks: &BlockStore, voters: &BTreeSet<PublicId>) -> bool {
        let from = self.from.into_block(blocks);
        let to = self.to.into_block(blocks);
        let members = if to.members.len() == from.members.len() - 1 &&
            from.members.difference(&to.members).count() == 1
        {
            &to.members
        } else {
            &from.members
        };
        is_quorum_of(voters, members)
    }
}

/// Return true if `voters` form a quorum of `members`.
fn is_quorum_of<T: Ord + Clone>(voters: &BTreeSet<T>, members: &BTreeSet<T>) -> bool {
    let valid_voters = voters & members;
    valid_voters.len() * QUORUM_DENOMINATOR > members.len() * QUORUM_NUMERATOR
}

#[cfg(test)]
mod test {
    use super::*;
    use id::FullId;

    fn random_public_id() -> PublicId {
        *FullId::new().public_id()
    }

    fn random_nodes(n: usize) -> Vec<PublicId> {
        (0..n).map(|_| random_public_id()).collect()
    }

    #[test]
    fn add_node() {
        let node1 = random_public_id();
        let node2 = random_public_id();
        let genesis = Block::genesis(node1.clone());
        let with_node2 = genesis.add_node(node2.clone());
        assert_eq!(with_node2.version, 1);
        assert_eq!(with_node2.prefix, genesis.prefix);
        assert_eq!(with_node2.members, btreeset!{ node1, node2 });
    }

    #[test]
    fn remove_node() {
        let node1 = random_public_id();
        let node2 = random_public_id();
        let genesis = Block::genesis(node1);
        let with_node2 = genesis.add_node(node2);
        let without_node2 = with_node2.remove_node(&node2);
        assert_eq!(without_node2.version, 2);
        assert_eq!(with_node2.prefix, genesis.prefix);
        assert_eq!(without_node2.members, btreeset!{ node1 });
    }

    #[test]
    fn is_admissible_after() {
        let nodes = random_nodes(3);

        let b0 = Block::genesis(nodes[0]);
        let b1a = b0.add_node(nodes[1]);
        let b1b = b0.add_node(nodes[2]);
        let b2 = b1a.add_node(nodes[2]);
        let b3 = b2.remove_node(&nodes[1]);

        // Single-version increments are OK.
        assert!(b1a.is_admissible_after(&b0));
        assert!(b1b.is_admissible_after(&b0));
        assert!(b2.is_admissible_after(&b1a));
        assert!(b3.is_admissible_after(&b2));

        // Blocks at the same version aren't admissible after each other.
        assert!(!b0.is_admissible_after(&b0));
        assert!(!b1b.is_admissible_after(&b1a));

        // b2 is admissible after b1b because it looks like an add relative to it:
        // {1, 3} => {1, 2, 3}
        assert!(b2.is_admissible_after(&b1b));

        // b2 is NOT admissible after b0.
        assert!(!b2.is_admissible_after(&b0));

        // However, b3 *is* admissible after b0.
        assert!(b3.is_admissible_after(&b0));
    }

    #[test]
    fn outranks_same_prefix() {
        let nodes = random_nodes(4);

        let b0 = Block::genesis(nodes[0]);
        let b1a = b0.add_node(nodes[1]);
        let b2a = b1a.add_node(nodes[2]);
        let b1b = b0.add_node(nodes[2]);
        let b2b = b1b.remove_node(&nodes[0]);
        let b2c = b1b.add_node(nodes[3]);

        // b2a with {1, 2, 3} outranks b2b with {3}.
        assert!(b2a.outranks(&b2b));
        // b2c with {1, 3, 4} outranks b2a {1, 2, 3}.
        assert!(b2c.outranks(&b2a));
        // b2a doesn't outrank itself.
        assert!(!b2a.outranks(&b2a));
    }
}
