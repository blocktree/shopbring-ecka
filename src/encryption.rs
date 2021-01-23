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

use num_bigint::BigUint;
use sm3::{Digest, Sm3};

use libsm::sm2::{ecc,signature};
use libsm::sm2::field::FieldElem;

#[inline]
fn u32_to_bytes(x: u32) -> Vec<u8> {
   let big_x = BigUint::from(x);
    let mut ret = big_x.to_bytes_be();
    let length = ret.len();
    for _i in 0..4 - length {
        ret.insert(0, 0);
    }
   ret
}

#[inline]
fn kdf(x: &[u8], y: &[u8], length: u32) -> Result<Vec<u8>, bool> {
    let mut c: Vec<u8> = Vec::new();
    let mut ct: u32 = 1;

    let mut i: u32 = 0;

    while i < (length + 31) / 32 {
        let mut h = Sm3::new();
        h.input(x);
        h.input(y);
        h.input(u32_to_bytes(ct));
        let hash = h.result();

        if i + 1 == ((length + 31) / 32) && length % 32 != 0 {
            c.append(&mut hash.to_vec()[..length as usize % 32].to_vec());
        } else {
            c.append(&mut hash.to_vec());
        }
        ct += 1;
        i += 1;
    }

    for i in 0..length {
        if *c.get(i as usize).unwrap() != 0 {
            return Ok(c);
        }
    }

    Err(false)
}


pub fn encrypt(public_key: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    if public_key.len() != 64 {
        return Err("invalid public key data".to_string());
    }
    if plain.len() == 0 {
        return Err("no plain data to encrypt".to_string());
    }

    let mut uncompressed_public_key:Vec<u8> = Vec::from([0x04 as u8]);
    uncompressed_public_key.append(&mut public_key.to_vec());

    let ecc_ctx = ecc::EccCtx::new();
    let sig_ctx = signature::SigCtx::new();
    loop {
        let mut c: Vec<u8> = Vec::new();

        let k = ecc_ctx.random_uint();
        let p1 = sig_ctx.pk_from_sk(&k);
        let (x1, y1) = ecc_ctx.to_affine(&p1);
        let p2 = ecc_ctx.bytes_to_point(uncompressed_public_key.as_slice());
        let p2 = ecc_ctx.mul(&k, &p2.unwrap());
        let (x2, y2) = ecc_ctx.to_affine(&p2);

        c.append(&mut x1.to_bytes());
        c.append(&mut y1.to_bytes());

        let mut sm3_ctx = Sm3::new();
        sm3_ctx.input(x2.to_bytes());
        sm3_ctx.input(plain);
        sm3_ctx.input(y2.to_bytes());
        let h = sm3_ctx.result();
        c.append(&mut h.as_slice().to_vec());

        let ct = kdf(&x2.to_bytes(), &y2.to_bytes(), plain.len() as u32);
        if ct.is_err() {
            continue
        }

        c.append(&mut ct.unwrap());

        for i in 0..plain.len() {
            c[96 + i] ^= plain[i];
        }

        c.insert(0, 0x04);
        return Ok(c);
    }
}

pub fn decrypt(private_key: &[u8], cipher: &[u8]) -> Result<Vec<u8>, String> {
    if cipher[0] != 0x04 || cipher.len() <= 97 {
        return Err("invalid cipher data".to_string());
    }
    if private_key.len() != 32 {
        return Err("invalid private key data".to_string());
    }

    let length = cipher.len() - 97;
    let ecc_ctx = ecc::EccCtx::new();

    let p2 = ecc_ctx.new_point(&FieldElem::from_bytes(&cipher[1..33]), &FieldElem::from_bytes(&cipher[33..65]));
    if p2.is_err() {
        return Err("decrypt point mul failed".to_string());
    }
    let p2 = ecc_ctx.mul(&BigUint::from_bytes_be(private_key), &p2.unwrap());
    let (x2, y2) = ecc_ctx.to_affine(&p2);

    let ct = kdf(&x2.to_bytes(), &y2.to_bytes(), length as u32);
    if ct.is_err() {
        return Err("decrypt kdf failed".to_string());
    }

    let mut c = ct.unwrap();
    for i in 0..length {
        c[i] ^= cipher[i + 97];
    }

    let mut sm3_ctx = Sm3::new();
    sm3_ctx.input(x2.to_bytes());
    sm3_ctx.input(c.clone());
    sm3_ctx.input(y2.to_bytes());
    let h = sm3_ctx.result();
    let h = h.as_slice();
    for i in 0..32 {
        if h[i] != cipher[65 + i] {
            return Err("decrypt check failed".to_string());
        }
    }
    Ok(c)
}

