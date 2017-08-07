use std::ops::Deref;
use std::collections::{BTreeSet, BTreeMap, HashMap};
use chain::block::{BlockId, Block};

pub struct BlockStore {
    map: HashMap<BlockId, Block>
}

impl BlockStore {
    pub fn new() -> BlockStore {
        BlockStore {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, block: Block) -> BlockId {
        let id = block.get_id();
        self.map.insert(id, block);
        id
    }

    pub fn get(&self, block_id: &BlockId) -> Option<&Block> {
        self.map.get(block_id)
    }
}
