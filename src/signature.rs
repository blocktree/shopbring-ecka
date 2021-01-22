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

#[inline]
fn der_decode(buf: &[u8]) -> Result<Vec<u8>, yasna::ASN1Error> {
    let (r, s) = yasna::parse_der(buf, |reader| {
        reader.read_sequence(|reader| {
            let r = reader.next().read_biguint()?;
            let s = reader.next().read_biguint()?;
            Ok((r, s))
        })
    })?;

    let mut rs = Vec::new();
    let mut r_bytes = r.to_bytes_be();
    let r_len = r_bytes.len();
    if r_len < 32 {
        Vec::append(&mut rs, &mut vec![0; 32 - r_len]);
    }
    Vec::append(&mut rs, &mut r_bytes);

    let mut s_bytes = s.to_bytes_be();
    let s_len = s_bytes.len();
    if s_len < 32 {
        Vec::append(&mut rs, &mut vec![0; 32 - s_len]);
    }
    Vec::append(&mut rs, &mut s_bytes);

    Ok(rs)
}

#[inline]
fn der_encode(sig: &[u8]) -> Vec<u8> {
    let r = BigUint::from_bytes_be(sig[..32].as_ref());
    let s = BigUint::from_bytes_be(sig[32..].as_ref());

    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_biguint(&r);
            writer.next().write_biguint(&s);
        })
    })
}

pub fn sign(private_key: &[u8], id: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    if id.len() * 8 > 65535 {
        return Err("ID is too long".to_string());
    }

    if private_key.len() != 32 {
        return Err("invalid private key length".to_string());
    }

    if message.len() == 0 {
        return Err("missing message".to_string());
    }

    let n = BigUint::from_str_radix(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        16,
    ).unwrap();

    let ctx = signature::SigCtx::new();
    let sk = BigUint::from_bytes_be(private_key);

    if sk >= n || sk == BigUint::zero() {
        return Err("invalid private key data".to_string());
    }

    let pk = ctx.pk_from_sk(&sk);
    let e = ctx.hash(id, &pk, message);
    let signature = ctx.sign_raw(&e[..], &sk);

    Ok(der_decode(signature.der_encode().as_slice()).unwrap())
}

pub fn verify(public_key: &[u8], id: &str, message: &[u8], signature: &[u8]) -> bool {
    if id.len() * 8 > 65535 || (public_key.len() != 64) || message.len() == 0 || signature.len() != 64 {
        return false;
    }

    let ctx = signature::SigCtx::new();
    let mut uncompressed_public_key:Vec<u8> = Vec::from([0x04 as u8]);
    uncompressed_public_key.append(&mut public_key.to_vec());
    let e = ctx.hash(id, &ctx.load_pubkey(uncompressed_public_key.as_slice()).unwrap(), message);

    let sig = signature::Signature::der_decode(der_encode(signature).as_slice());

    ctx.verify_raw(&e, &ctx.load_pubkey(uncompressed_public_key.as_slice()).unwrap(), &sig.unwrap())
}

#[cfg(test)]
mod tests {
    use crate::signature::{sign, verify};

    #[test]
    fn test_sign() {
        let private_key: [u8; 32] = [54, 252, 224, 48, 18, 145, 4, 133, 146, 167, 11, 6, 102, 93, 223, 186, 226, 78, 216, 21, 94, 170, 9, 209, 120, 113, 182, 41, 122, 249, 28, 104];
        let public_key: [u8; 64] = [160, 197, 40, 160, 163, 227, 170, 124, 8, 81, 232, 160, 246, 179, 113, 56, 112, 201, 157, 192, 150, 131, 167, 136, 126, 185, 62, 46, 105, 179, 116, 44, 166, 106, 76, 29, 85, 178, 11, 238, 194, 199, 42, 45, 225, 150, 163, 70, 214, 239, 134, 157, 205, 172, 164, 5, 21, 255, 185, 131, 180, 163, 220, 25];

        let message: [u8; 4] = [11,22,33,44];
        let id = "signer";

        let signature = sign(&private_key, id, &message);

        assert!(verify(&public_key, id, &message, signature.unwrap().as_slice()))
    }

}