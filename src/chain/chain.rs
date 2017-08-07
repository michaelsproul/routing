use chain::block::{Block, BlockId};
use chain::block_store::BlockStore;
use chain::vote_store::VoteStore;
use std::collections::BTreeSet;

/// Section membership chain containing history of the network's structure.
pub struct Chain {
    /// Store of all blocks that we know of. Contains the actual `Block` structs.
    block_store: BlockStore,
    /// Store of all votes that we know of. Contains the actual `SignedVote` structs.
    vote_store: VoteStore,
    /// Set of block IDs of all blocks we know to be valid.
    valid_blocks: BTreeSet<BlockId>,
    /// Set of block IDs of all blocks we know to be current.
    current_blocks: BTreeSet<BlockId>,
}

impl Chain {
    /// Initialise a chain with a set of blocks that we accept as valid.
    pub fn with_blocks(blocks: BTreeSet<Block>) -> Self {
        let mut block_store = BlockStore::new();
        let mut valid_blocks = BTreeSet::new();

        for block in blocks {
            let block_id = block_store.insert(block);
            valid_blocks.insert(block_id);
        }

        Chain {
            block_store,
            vote_store: VoteStore::new(),
            valid_blocks,
            // FIXME(michael): compute current blocks from valid blocks.
            current_blocks: BTreeSet::new(),
        }
    }
}
