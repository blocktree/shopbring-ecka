// Copyright (C) 2017-2021 blocktree.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use libsm::sm2::signature;
use num_bigint::BigUint;
use num_traits::*;

pub fn generate_public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>, String> {
    if private_key.len() != 32 {
        return Err("invalid private key length".to_string());
    }
    let ctx = signature::SigCtx::new();
    let sk = BigUint::from_bytes_be(private_key);
    let n = BigUint::from_str_radix(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        16,
    ).unwrap();

    if sk >= n || sk == BigUint::zero() {
        Err("invalid private key data".to_string())
    } else {
        let public_key_point = ctx.pk_from_sk(&sk);
        Ok(
            ctx.serialize_pubkey(&public_key_point, false)[1..].to_vec()
        )
    }
}



#[cfg(test)]
mod tests {
    use crate::key_generation::generate_public_key_from_private;

    #[test]
    fn test_generate_public_key_from_private() {
        let private_key: [u8; 32] = [152,140,107,109,220,212,209,1,200,39,157,39,137,2,70,102,75,101,53,234,47,39,138,140,141,111,213,25,241,74,231,123];
        let expect_public_key: [u8; 64] = [46, 23, 193, 87, 75, 239, 54, 252, 224, 48, 18, 145, 4, 133, 146, 167, 11, 6, 102, 93, 223, 186, 226, 78, 216, 21, 94, 170, 9, 209, 120, 113, 182, 41, 122, 249, 28, 104, 113, 184, 237, 61, 177, 184, 130, 164, 178, 234, 62, 227, 79, 159, 156, 165, 11, 89, 179, 211, 252, 16, 0, 16, 46, 128];
        let public_key = generate_public_key_from_private(&private_key);

        assert!(public_key.is_ok());
        assert_eq!(public_key.unwrap().as_slice(), expect_public_key)
    }

    #[test]
    fn test_invalid_private_key() {
        let private_key = hex::decode("9d27890246664b6535ea2f278a8c8d");

        let public_key = generate_public_key_from_private(private_key.unwrap().as_slice());

        assert!(public_key.is_err());


        let private_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000000");

        let public_key = generate_public_key_from_private(private_key.unwrap().as_slice());

        assert!(public_key.is_err());
    }

 }
