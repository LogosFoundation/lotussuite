use crate::{BytesMut, Hashed};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MerkleMode {
    Bitcoin,
    Lotus,
}

pub fn get_merkle_root<H: Hashed + Clone>(leaves: Vec<H>, mode: MerkleMode) -> H {
    get_merkle_root_and_height(leaves, mode).0
}

pub fn get_merkle_root_and_height<H: Hashed + Clone>(
    mut leaves: Vec<H>,
    mode: MerkleMode,
) -> (H, usize) {
    if leaves.is_empty() {
        return (H::from_array(H::Array::default()), 0);
    }
    let mut height = 1;
    while leaves.len() > 1 {
        height += 1;
        if leaves.len() % 2 == 1 {
            match mode {
                // repeat last hash to make num leaves even on Bitcoin
                MerkleMode::Bitcoin => leaves.push(leaves.last().unwrap().clone()),
                // add 0000...000000 to make num leaves even on Lotus
                MerkleMode::Lotus => leaves.push(H::from_array(H::Array::default())),
            }
        }
        let mut next_layer = Vec::new();
        for pair in leaves.chunks_exact(2) {
            let mut bytes = BytesMut::new();
            bytes.put_slice(pair[0].as_slice());
            bytes.put_slice(pair[1].as_slice());
            next_layer.push(H::digest(&bytes.freeze()));
        }
        leaves = next_layer;
    }
    (leaves.remove(0), height)
}
