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

mod key_generation;
mod signature;
mod encryption;
mod key_agreement;

#[cfg(test)]
mod tests {
    use crate::key_generation::*;
    use crate::signature::*;
    use crate::encryption::*;
    use crate::key_agreement::*;

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

    #[test]
    fn test_sign() {
        let private_key: [u8; 32] = [54, 252, 224, 48, 18, 145, 4, 133, 146, 167, 11, 6, 102, 93, 223, 186, 226, 78, 216, 21, 94, 170, 9, 209, 120, 113, 182, 41, 122, 249, 28, 104];
        let public_key: [u8; 64] = [160, 197, 40, 160, 163, 227, 170, 124, 8, 81, 232, 160, 246, 179, 113, 56, 112, 201, 157, 192, 150, 131, 167, 136, 126, 185, 62, 46, 105, 179, 116, 44, 166, 106, 76, 29, 85, 178, 11, 238, 194, 199, 42, 45, 225, 150, 163, 70, 214, 239, 134, 157, 205, 172, 164, 5, 21, 255, 185, 131, 180, 163, 220, 25];

        let message: [u8; 4] = [11,22,33,44];
        let id = "signer";

        let signature = sign(&private_key, id, &message);

        assert!(verify(&public_key, id, &message, signature.unwrap().as_slice()))
    }

    #[test]
    fn test_encryption() {
        let private_key: [u8; 32] = [3, 172, 194, 4, 51, 104, 150, 46, 94, 221, 133, 33, 220, 132, 145, 166, 222, 42, 109, 38, 143, 234, 127, 141, 96, 108, 220, 124, 199, 122, 18, 176];
        let public_key: [u8; 64] = [159, 33, 15, 91, 218, 164, 218, 245, 154, 38, 18, 194, 196, 168, 74, 117, 188, 103, 252, 143, 58, 252, 193, 252, 160, 75, 226, 45, 29, 17, 224, 148, 248, 228, 181, 77, 198, 215, 21, 108, 73, 251, 129, 39, 203, 166, 199, 110, 204, 49, 98, 67, 115, 178, 238, 46, 163, 159, 75, 45, 153, 181, 183, 138];

        let plain:[u8; 4] = [1,2,3,4];

        let cipher = encrypt(&public_key, &plain);
        assert!(cipher.is_ok());

        let check = decrypt(&private_key, cipher.unwrap().as_slice());
        assert!(check.is_ok());

        assert_eq!(plain.to_vec(), check.unwrap())
    }

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
