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

use sm3::{Sm3, Digest};
use libsm::sm2::{ecc, signature};
use libsm::sm2::field::FieldElem;
use num_bigint::BigUint;
use byteorder::{WriteBytesExt, BigEndian};
use libsm::sm3::hash::Sm3Hash;
use std::ops::{Mul, Add};
use num_integer::Integer;

#[inline]
fn za(public_key: &[u8], uid: &str, curve: &ecc::EccCtx) -> Vec<u8> {

    let mut prepend: Vec<u8> = Vec::new();
    if uid.len() * 8 > 65535 {
        panic!("ID is too long.");
    }
    prepend
        .write_u16::<BigEndian>((uid.len() * 8) as u16)
        .unwrap();
    for c in uid.bytes() {
        prepend.push(c);
    }

    let mut a = curve.get_a();
    let mut b = curve.get_b();

    prepend.append(&mut a);
    prepend.append(&mut b);

    let (x_g, y_g) = curve.to_affine(&curve.generator());
    let (mut x_g, mut y_g) = (x_g.to_bytes(), y_g.to_bytes());
    prepend.append(&mut x_g);
    prepend.append(&mut y_g);

    prepend.append(&mut public_key.to_vec());

    let mut hasher = Sm3Hash::new(&prepend[..]);
    hasher.get_hash().to_vec()
}

#[inline]
fn ka_kdf(public_key: &[u8], z_initiator: &[u8], z_responder: &[u8], key_length_bit: u16) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::new();

    let mut generator:[u8;4] = [0; 4];
    let h_len_1: u32;

    if key_length_bit % 256 == 0 {
        h_len_1 = (key_length_bit / 256) as u32;
    } else {
        h_len_1 = ((key_length_bit / 256) + 1) as u32;
    }

    for i in 1..h_len_1+1 {
        generator[0] = ((i >> 24) & 0xff) as u8;
        generator[1] = ((i >> 16) & 0xff) as u8;
        generator[2] = ((i >> 8) & 0xff) as u8;
        generator[3] = (i & 0xff) as u8;

        let mut h = Sm3::new();
        h.input(public_key);
        h.input(z_initiator);
        h.input(z_responder);
        h.input(&generator);
        let hash = h.result();

        if key_length_bit >= 256 {
            key.append(&mut hash.to_vec());
        } else {
            key.append(&mut hash.to_vec()[..(key_length_bit / 8) as usize].to_vec())
        }
    }

    key
}

#[inline]
fn ka_check(value: u8, z_initiator: &[u8], z_responder: &[u8], r_initiator: &[u8], r_responder: &[u8], uv: &[u8]) -> Vec<u8> {
    let mut sm3_ctx1 = Sm3::new();
    sm3_ctx1.input(uv[..32].to_vec());
    sm3_ctx1.input(z_initiator);
    sm3_ctx1.input(z_responder);
    sm3_ctx1.input(r_initiator);
    sm3_ctx1.input(r_responder);
    let tmp = sm3_ctx1.result();

    let mut sm3_ctx2 = Sm3::new();
    sm3_ctx2.input([value]);
    sm3_ctx2.input(uv[32..].to_vec());
    sm3_ctx2.input(tmp.as_slice());
    sm3_ctx2.result().to_vec()
}

#[derive(Clone)]
pub struct InitiatorStep1 {
    tmp_private_key: Vec<u8>,
    tmp_public_key : Vec<u8>
}

impl InitiatorStep1 {
    pub fn new(private: Vec<u8>, public: Vec<u8>) -> InitiatorStep1 {
        InitiatorStep1{
            tmp_private_key: private,
            tmp_public_key: public
        }
    }
    #[inline]
    pub fn get_tmp_private_key(&self) -> &Vec<u8> { &self.tmp_private_key }
    #[inline]
    pub fn get_tmp_public_key(&self) -> &Vec<u8> { &self.tmp_public_key }
}

pub fn key_agreement_initiator_step1() -> Result<InitiatorStep1, String> {
    let ecc_ctx = ecc::EccCtx::new();
    let sig_ctx = signature::SigCtx::new();

    let random = ecc_ctx.random_uint();

    let random_pub = sig_ctx.pk_from_sk(&random);

    let mut tmp_private_key = random.to_bytes_be();
    if tmp_private_key.len() < 32 {
        let offset = 32 - tmp_private_key.len();
        for _ in 0..32 - offset {
            tmp_private_key.insert(0, 0);
        }
    }

    let (x, y) = ecc_ctx.to_affine(&random_pub);

    let mut tmp_public_key: Vec<u8> = Vec::new();
    tmp_public_key.append(&mut x.to_bytes());
    tmp_public_key.append(&mut y.to_bytes());
    Ok(InitiatorStep1::new(tmp_private_key, tmp_public_key))
}


#[derive(Clone)]
pub struct InitiatorStep2 {
    key: Vec<u8>,
    s:   Vec<u8>
}

impl InitiatorStep2 {
    #[inline]
    pub fn get_key(&self) -> &Vec<u8> { &self.key }
    #[inline]
    pub fn get_s(&self) -> &Vec<u8> { &self.s }
}

pub fn key_agreement_initiator_step2 (id_initiator: &str,
                                      id_responder: &str,
                                      private_key_initiator: &[u8],
                                      public_key_initiator: &[u8],
                                      public_key_responder: &[u8],
                                      tmp_private_key_initiator: &[u8],
                                      tmp_public_key_initiator: &[u8],
                                      tmp_public_key_responder: &[u8],
                                      s_responder: &[u8],
                                      key_length: u16
) -> Result<InitiatorStep2, String> {
    if id_initiator.len() == 0 || id_initiator.len() >= 8192 { return Err("invalid initiator's id length".to_string()) }
    if id_responder.len() == 0 || id_responder.len() >= 8192 { return Err("invalid responder's id length".to_string()) }
    if private_key_initiator.len() != 32 { return Err("invalid initiator's private key length".to_string()) }
    if public_key_initiator.len() != 64 { return  Err("invalid initiator's public key length".to_string()) }
    if public_key_responder.len() != 64 { return Err("invalid responder's public key length".to_string()) }
    if tmp_private_key_initiator.len() != 32 { return Err("invalid initiator's temp private key length".to_string()) }
    if tmp_public_key_initiator.len() != 64 { return Err("invalid initiator's temp public key length".to_string()) }
    if tmp_public_key_responder.len() != 64 { return Err("invalid responder's temp public key length".to_string()) }
    if s_responder.len() != 32 { return Err("invalid responder's check length (s)".to_string()) }
    if key_length == 0 { return Err("invalid key length (0)".to_string()) }

    let ecc_ctx = ecc::EccCtx::new();
    let point1 = ecc_ctx.new_point(&FieldElem::from_bytes(&tmp_public_key_responder[..32]), &FieldElem::from_bytes(&tmp_public_key_responder[32..]));
    if point1.is_err() {
        return Err("invalid responder's temp public key data".to_string());
    }
    if ecc_ctx.new_point(&FieldElem::from_bytes(&tmp_public_key_initiator[..32]), &FieldElem::from_bytes(&tmp_public_key_initiator[32..])).is_err() {
        return Err("invalid initiator's temp public key data".to_string());
    }

    let mut tmp1_bytes: Vec<u8> = Vec::new();
    tmp1_bytes.append(&mut tmp_public_key_initiator[16..32].to_vec());
    tmp1_bytes[0] |= 0x80;

    let tmp1 = BigUint::from_bytes_be(tmp1_bytes.as_slice());
    let tmp2 = tmp1.mul(BigUint::from_bytes_be(tmp_private_key_initiator));
    let tmp1 = tmp2.clone().add(BigUint::from_bytes_be(private_key_initiator));
    let (_, tmp1) = tmp1.div_rem(&ecc_ctx.n);

    let mut tmp2_bytes: Vec<u8> = Vec::from([0 as u8; 16]);
    tmp2_bytes.append(&mut tmp_public_key_responder[16..32].to_vec());
    tmp2_bytes[16] |= 0x80;

    let mut point1 = ecc_ctx.mul(&BigUint::from_bytes_be(tmp2_bytes.as_slice()), &point1.unwrap());
    point1 = ecc_ctx.add(&point1, &ecc_ctx.new_point(&FieldElem::from_bytes(&public_key_responder[..32]), &FieldElem::from_bytes(&public_key_responder[32..])).unwrap());
    point1 = ecc_ctx.mul(&tmp1, &point1);
    let z_initiator = za(public_key_initiator, id_initiator, &ecc_ctx);
    let z_responder = za(public_key_responder, id_responder, &ecc_ctx);

    let sig_ctx = signature::SigCtx::new();
    let key = ka_kdf(&sig_ctx.serialize_pubkey(&point1, false)[1..], z_initiator.as_slice(), z_responder.as_slice(), key_length * 8);
    let s_check = ka_check(0x02, z_initiator.as_slice(), z_responder.as_slice(), tmp_public_key_initiator, tmp_public_key_responder, &sig_ctx.serialize_pubkey(&point1, false)[1..]);

    for i in 0..32 {
        if s_check[i] != s_responder[i] {
            return Err("check failed".to_string());
        }
    }

    Ok(InitiatorStep2{ key, s: ka_check(0x03, z_initiator.as_slice(), z_responder.as_slice(), tmp_public_key_initiator, tmp_public_key_responder, &sig_ctx.serialize_pubkey(&point1, false)[1..]) })
}

#[derive(Clone)]
pub struct ResponderStep1 {
    key: Vec<u8>,
    tmp_public_key: Vec<u8>,
    s_inner: Vec<u8>,
    s_outer: Vec<u8>
}

impl ResponderStep1 {
    #[inline]
    pub fn get_key(&self) -> &Vec<u8> { &self.key }
    #[inline]
    pub fn get_tmp_public_key(&self) -> &Vec<u8> { &self.tmp_public_key }
    #[inline]
    pub fn get_s_inner(&self) -> &Vec<u8> { &self.s_inner }
    #[inline]
    pub fn get_s_outer(&self) -> &Vec<u8> { &self.s_outer }
}

pub fn key_agreement_responder_step1(id_initiator: &str,
                                     id_responder: &str,
                                     private_key_responder: &[u8],
                                     public_key_responder: &[u8],
                                     public_key_initiator: &[u8],
                                     tmp_public_key_initiator: &[u8],
                                     key_length: u16) -> Result<ResponderStep1, String> {

    if id_initiator.len() == 0 || id_initiator.len() >= 8192 { return Err("invalid initiator's id length".to_string()) }
    if id_responder.len() == 0 || id_responder.len() >= 8192 { return Err("invalid responder's id length".to_string()) }
    if private_key_responder.len() != 32 { return Err("invalid responder's private key length".to_string()) }
    if public_key_responder.len() != 64 { return Err("invalid responder's public key length".to_string()) }
    if public_key_initiator.len() != 64 { return  Err("invalid initiator's public key length".to_string()) }
    if tmp_public_key_initiator.len() != 64 { return Err("invalid initiator's temp public key length".to_string()) }
    if key_length == 0 { return Err("invalid key length (0)".to_string()) }

    let ecc_ctx = ecc::EccCtx::new();
    let point1 = ecc_ctx.new_point(&FieldElem::from_bytes(&tmp_public_key_initiator[..32]), &FieldElem::from_bytes(&tmp_public_key_initiator[32..]));
    if point1.is_err() {
        return Err("invalid initiator's temp public key data".to_string());
    }

    let ecc_ctx = ecc::EccCtx::new();
    let sig_ctx = signature::SigCtx::new();

    let tmp_private_key_responder = ecc_ctx.random_uint();

    let tmp_public_key_responder = sig_ctx.pk_from_sk(&tmp_private_key_responder);

    let mut tmp1_bytes: Vec<u8> = Vec::new();
    tmp1_bytes.append(&mut sig_ctx.serialize_pubkey(&tmp_public_key_responder, false)[17..33].to_vec());
    tmp1_bytes[0] |= 0x80;

    let tmp1 = BigUint::from_bytes_be(tmp1_bytes.as_slice());
    let tmp2 = tmp1.mul(tmp_private_key_responder);
    let tmp1 = tmp2.clone().add(BigUint::from_bytes_be(private_key_responder));
    let (_, tmp1) = tmp1.div_rem(&ecc_ctx.n);

    let mut tmp2_bytes: Vec<u8> = Vec::from([0 as u8; 16]);
    tmp2_bytes.append(&mut tmp_public_key_initiator[16..32].to_vec());
    tmp2_bytes[16] |= 0x80;

    let mut point1 = ecc_ctx.mul(&BigUint::from_bytes_be(tmp2_bytes.as_slice()), &point1.unwrap());
    point1 = ecc_ctx.add(&point1, &ecc_ctx.new_point(&FieldElem::from_bytes(&public_key_initiator[..32]), &FieldElem::from_bytes(&public_key_initiator[32..])).unwrap());
    point1 = ecc_ctx.mul(&tmp1, &point1);

    let z_initiator = za(public_key_initiator, id_initiator, &ecc_ctx);
    let z_responder = za(public_key_responder, id_responder, &ecc_ctx);

    let key = ka_kdf(&sig_ctx.serialize_pubkey(&point1, false)[1..], z_initiator.as_slice(), z_responder.as_slice(), key_length * 8);
    let s_inner = ka_check(0x03, z_initiator.as_slice(), z_responder.as_slice(), tmp_public_key_initiator, &sig_ctx.serialize_pubkey(&tmp_public_key_responder, false)[1..], &sig_ctx.serialize_pubkey(&point1, false)[1..]);
    let s_outer = ka_check(0x02, z_initiator.as_slice(), z_responder.as_slice(), tmp_public_key_initiator, &sig_ctx.serialize_pubkey(&tmp_public_key_responder, false)[1..], &sig_ctx.serialize_pubkey(&point1, false)[1..]);
    Ok(ResponderStep1{
        key,
        tmp_public_key: sig_ctx.serialize_pubkey(&tmp_public_key_responder, false)[1..].to_vec(),
        s_inner,
        s_outer
    })
}

pub fn key_agreement_responder_step2(s_initiator: &[u8], s_responder: &[u8]) -> bool {
    if s_initiator.len()!= 32 || s_responder.len() != 32 {
        false
    } else {
        for i in 0..32 {
            if s_responder[i] != s_initiator[i] {
                return false;
            }
        }
        true
    }
}
#[cfg(test)]
mod tests {
    use crate::key_agreement::{key_agreement_initiator_step1, key_agreement_responder_step1, key_agreement_initiator_step2, key_agreement_responder_step2};

    #[test]
    fn test_key_agreement() {
        let initiator_private_key: [u8; 32] = [170, 145, 43, 121, 36, 102, 170, 247, 183, 16, 142, 209, 92, 105, 52, 23, 237, 46, 171, 66, 114, 231, 96, 172, 19, 196, 227, 74, 228, 69, 66, 69];
        let initiator_public_key: [u8; 64] = [3, 172, 194, 4, 51, 104, 150, 46, 94, 221, 133, 33, 220, 132, 145, 166, 222, 42, 109, 38, 143, 234, 127, 141, 96, 108, 220, 124, 199, 122, 18, 176, 103, 194, 131, 73, 133, 207, 212, 184, 125, 222, 205, 155, 176, 44, 152, 40, 152, 37, 84, 80, 171, 140, 89, 105, 41, 3, 253, 171, 232, 138, 47, 1];
        let id_initiator = "initiator";

        let responder_private_key: [u8; 32] = [156, 218, 46, 111, 146, 196, 105, 103, 159, 142, 223, 212, 195, 218, 247, 81, 84, 190, 150, 26, 199, 194, 247, 95, 88, 143, 145, 32, 21, 163, 144, 193];
        let responder_public_key: [u8; 64] = [170, 145, 43, 121, 36, 102, 170, 247, 183, 16, 142, 209, 92, 105, 52, 23, 237, 46, 171, 66, 114, 231, 96, 172, 19, 196, 227, 74, 228, 69, 66, 69, 170, 106, 115, 140, 123, 73, 77, 180, 236, 241, 154, 132, 77, 26, 59, 171, 134, 66, 142, 3, 235, 97, 22, 42, 168, 16, 173, 122, 168, 15, 63, 80];
        let id_responder = "responder";

        let key_length: u16 = 8;

        // initiator step 1
        let initiator_step1 = key_agreement_initiator_step1();
        if initiator_step1.is_ok() {
            println!("initiator's temp private key : {:?}", initiator_step1.clone().unwrap().get_tmp_private_key());
            println!("initiator's temp public key : {:?}", initiator_step1.clone().unwrap().get_tmp_public_key());
        } else {
            println!("{:?}", initiator_step1.err());
            return
        }

        // responder step 1
        let responder_step1 = key_agreement_responder_step1(
            id_initiator,
            id_responder,
            &responder_private_key,
            &responder_public_key,
            &initiator_public_key,
            initiator_step1.clone().unwrap().get_tmp_public_key().as_slice(),
            key_length);

        if responder_step1.is_ok() {
            println!("responder's temp public key : {:?}", responder_step1.clone().unwrap().get_tmp_public_key());
            println!("responder's agreement result : {:?}", responder_step1.clone().unwrap().get_key());
            println!("responder's local check hash : {:?}", responder_step1.clone().unwrap().get_s_inner());
            println!("responder's check hash to send : {:?}", responder_step1.clone().unwrap().get_s_outer());
        } else {
            println!("{:?}", responder_step1.err());
            return
        }

        // initiator step 2
        let initiator_step2 = key_agreement_initiator_step2(
            id_initiator,
            id_responder,
            &initiator_private_key,
            &initiator_public_key,
            &responder_public_key,
            initiator_step1.clone().unwrap().get_tmp_private_key().as_slice(),
            initiator_step1.clone().unwrap().get_tmp_public_key().as_slice(),
            responder_step1.clone().unwrap().get_tmp_public_key().as_slice(),
            responder_step1.clone().unwrap().get_s_outer().as_slice(),
            key_length
        );

        if initiator_step2.is_ok() {
            println!("initiator's agreement result : {:?}", initiator_step2.clone().unwrap().get_key());
            println!("initiator's check hash to send : {:?}", initiator_step2.clone().unwrap().get_s());
        } else {
            println!("{:?}", initiator_step2.clone().err())
        }

        // responder step 2
        let pass = key_agreement_responder_step2(initiator_step2.clone().unwrap().get_s(), responder_step1.clone().unwrap().get_s_inner());

        assert!(pass);
        assert_eq!(initiator_step2.clone().unwrap().get_key(), responder_step1.clone().unwrap().get_key())
    }
}