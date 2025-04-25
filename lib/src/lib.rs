use alloy_sol_types::sol;
use sha2::{Digest, Sha256};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes32  begin_hash;
        bytes32  end_hash;
    }
}

pub fn double_sha256(input: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(Sha256::digest(input).to_vec()).to_vec();
    hash.try_into().expect("Hash length is not 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_sha256() {
        let input = hex::decode("01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed").unwrap();
        let result = double_sha256(input.as_slice());
        let expected =
            hex::decode("3c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000")
                .unwrap();
        assert_eq!(result.to_vec(), expected);
    }
}

