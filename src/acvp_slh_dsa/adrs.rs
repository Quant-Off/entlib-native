use crate::acvp_slh_dsa::slh_dsa_params::to_byte;

#[derive(Clone, Copy, Debug)]
pub struct Adrs {
    // 32-byte address structure as specified in Section 4.2 [cite: 2122]
    // Layout: layer(4) | tree(12) | type(4) | words(12) [cite: 2138]
    pub data: [u8; 32],
}

impl Adrs {
    pub fn new() -> Self {
        Self { data: [0u8; 32] }
    }

    // [cite: 2241] Table 1. Member functions for addresses
    pub fn set_layer_address(&mut self, layer: u32) {
        // ADRS[0:4] <- toByte(layer, 4)
        let bytes = to_byte(layer, 4);
        self.data[0..4].copy_from_slice(&bytes);
    }

    pub fn set_tree_address(&mut self, tree: u64) {
        self.data[4..16].fill(0);
        let bytes = tree.to_be_bytes();
        self.data[8..16].copy_from_slice(&bytes);
    }

    pub fn set_type_and_clear(&mut self, type_val: u32) {
        // [cite: 2241] ADRS.setTypeAndClear(Y): ADRS[16:20] <- toByte(Y, 4); ADRS[20:32] <- toByte(0, 12)
        let bytes = to_byte(type_val, 4);
        self.data[16..20].copy_from_slice(&bytes);
        self.data[20..32].fill(0);
    }

    pub fn set_key_pair_address(&mut self, addr: u32) {
        // [cite: 2241] ADRS[20:24] <- toByte(i, 4)
        let bytes = to_byte(addr, 4);
        self.data[20..24].copy_from_slice(&bytes);
    }

    pub fn set_chain_address(&mut self, addr: u32) {
        // [cite: 2241] ADRS[24:28] <- toByte(i, 4)
        let bytes = to_byte(addr, 4);
        self.data[24..28].copy_from_slice(&bytes);
    }

    pub fn set_hash_address(&mut self, addr: u32) {
        // [cite: 2241] ADRS[28:32] <- toByte(i, 4)
        let bytes = to_byte(addr, 4);
        self.data[28..32].copy_from_slice(&bytes);
    }

    // Helper mappings for specific address types (e.g., TREE, FORS_TREE) [cite: 2176, 2200]
    pub fn set_tree_height(&mut self, height: u32) {
        // In TREE/FORS_TREE, height is at the same offset as chain address (bytes 24..28)
        self.set_chain_address(height);
    }

    pub fn set_tree_index(&mut self, index: u32) {
        // In TREE/FORS_TREE, index is at the same offset as hash address (bytes 28..32)
        self.set_hash_address(index);
    }
}

// Address Types [cite: 2162]
pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;