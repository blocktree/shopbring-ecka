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
