/*
    This file is part of OpenTSS.
    Copyright (C) 2022 LatticeX Foundation.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use crate::utilities::cl_proof::*;
use crate::utilities::class_group::PK;
use crate::utilities::class_group::*;
use crate::utilities::dl_com_zk::*;
use crate::utilities::elgamal::ElgamalCipher;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::promise_sigma_multi::{
    PromiseCipher as MulPromiseCipher, PromiseProof as MulPromiseProof,
    PromiseState as MulPromiseState,
};
use crate::{CU, FE, GE};
use classgroup::gmp::mpz::Mpz;
use classgroup::gmp_classgroup::GmpClassGroup;
use classgroup::ClassGroup;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::Scalar;
use curv::BigInt;
use curv::HashChoice;

pub trait EcdsaSeDe {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError>;
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError>;
}

impl EcdsaSeDe for DLCommitments {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.pk_commitment.to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        vec.append(&mut self.zk_pok_commitment.to_bytes());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let pk_commitment = BigInt::from_bytes(&msg[0..32]);
        let zk_pok_commitment = BigInt::from_bytes(&msg[32..msg.len()]);
        Ok(Box::new(DLCommitments {
            pk_commitment,
            zk_pok_commitment,
        }))
    }
}

impl EcdsaSeDe for Mpz {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let bigint = mpz_to_bigint(self);
        let mut vec: Vec<u8> = bigint.to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let bigint = BigInt::from_bytes(msg);
        Ok(Box::new(bigint_to_mpz(&bigint)))
    }
}

impl EcdsaSeDe for FE {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.to_bigint().to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        Ok(Box::new(Scalar::from(&BigInt::from_bytes(&msg))))
    }
}

impl EcdsaSeDe for GE {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.x_coord().unwrap().to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        let mut vec2 = self.y_coord().unwrap().to_bytes();
        if vec2.len() < 32 {
            let mut vec3 = vec![0; 32 - vec2.len()];
            vec3.extend_from_slice(&vec2);
            vec2 = vec3;
        }
        vec.append(&mut vec2);
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let x = BigInt::from_bytes(&msg[0..32]);
        let y = BigInt::from_bytes(&msg[32..64]);
        Ok(Box::new(GE::from_coords(&x, &y).unwrap()))
    }
}

// 160
impl EcdsaSeDe for DLogProof<CU, sha2::Sha256> {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.pk).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.pk_t_rand_commitment).unwrap());
        let mut vec1 = self.challenge_response.to_bigint().to_bytes();
        if vec1.len() < 32 {
            let mut vec2 = vec![0; 32 - vec1.len()];
            vec2.extend_from_slice(&vec1);
            vec1 = vec2;
        }
        vec.append(&mut vec1);
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let pk: GE = *EcdsaSeDe::deserialize(&msg[0..64].to_owned()).unwrap();
        let pk_t_rand_commitment: GE = *EcdsaSeDe::deserialize(&msg[64..128].to_owned()).unwrap();
        let challenge_response: FE = Scalar::from(&BigInt::from_bytes(&msg[128..msg.len()]));
        Ok(Box::new(DLogProof::<CU, sha2::Sha256> {
            pk,
            pk_t_rand_commitment,
            challenge_response,
            hash_choice: HashChoice::new(),
        }))
    }
}

// 288
impl EcdsaSeDe for CommWitness {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.pk_commitment_blind_factor.to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        let mut vec2 = self.zk_pok_blind_factor.to_bytes();
        if vec2.len() < 32 {
            let mut vec1 = vec![0; 32 - vec2.len()];
            vec1.extend_from_slice(&vec2);
            vec2 = vec1;
        }
        vec.append(&mut vec2);
        vec.append(&mut EcdsaSeDe::serialize(&self.public_share).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.d_log_proof).unwrap());
        return Ok(vec);
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let pk_commitment_blind_factor = BigInt::from_bytes(&msg[0..32]);
        let zk_pok_blind_factor = BigInt::from_bytes(&msg[32..64]);
        let public_share: GE = *EcdsaSeDe::deserialize(&msg[64..128].to_owned()).unwrap();
        let d_log_proof: DLogProof<CU, sha2::Sha256> =
            *EcdsaSeDe::deserialize(&msg[128..msg.len()].to_owned()).unwrap();
        Ok(Box::new(CommWitness {
            pk_commitment_blind_factor,
            zk_pok_blind_factor,
            public_share,
            d_log_proof,
        }))
    }
}

// 334
impl EcdsaSeDe for GmpClassGroup {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut buf: Vec<u8> = vec![0; 334];
        ClassGroup::serialize(self, &mut buf).unwrap();
        Ok(buf)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        Ok(Box::new(ClassGroup::deserialize(
            &msg,
            (*DISCRIMINANT_1827).clone(),
        )))
    }
}

// 668
impl EcdsaSeDe for Ciphertext {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.c1).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.c2).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let c1 = *EcdsaSeDe::deserialize(&msg[0..334].to_owned()).unwrap();
        let c2 = *EcdsaSeDe::deserialize(&msg[334..668].to_owned()).unwrap();
        Ok(Box::new(Ciphertext { c1, c2 }))
    }
}

impl EcdsaSeDe for CLProof {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.t1).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.t2).unwrap());
        let mut vec1 = EcdsaSeDe::serialize(&self.u1).unwrap();
        if vec1.len() < 162 {
            let mut vec2 = vec![0; 162 - vec1.len()];
            vec2.extend_from_slice(&vec1);
            vec1 = vec2;
        }
        vec.append(&mut vec1);
        vec.append(&mut EcdsaSeDe::serialize(&self.u2).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let t1: GmpClassGroup = *EcdsaSeDe::deserialize(&msg[0..334].to_owned()).unwrap();
        let t2: GmpClassGroup = *EcdsaSeDe::deserialize(&msg[334..668].to_owned()).unwrap();
        let u1: Mpz = *EcdsaSeDe::deserialize(&msg[668..830].to_owned()).unwrap();
        let u2: Mpz = *EcdsaSeDe::deserialize(&msg[830..msg.len()].to_owned()).unwrap();
        Ok(Box::new(CLProof { t1, t2, u1, u2 }))
    }
}

impl EcdsaSeDe for CLState {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.cipher).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.cl_pub_key.0).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let cipher: Ciphertext = *EcdsaSeDe::deserialize(&msg[0..668].to_owned()).unwrap();
        let cl_pub_key: PK = PK(*EcdsaSeDe::deserialize(&msg[668..msg.len()].to_owned()).unwrap());
        Ok(Box::new(CLState { cipher, cl_pub_key }))
    }
}

impl EcdsaSeDe for DlogCommitmentOpen {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.public_share).unwrap();
        vec.append(&mut self.blind_factor.to_bytes());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let public_share: GE = *EcdsaSeDe::deserialize(&msg[0..64].to_owned()).unwrap();
        let blind_factor: BigInt = BigInt::from_bytes(&msg[64..msg.len()]);
        Ok(Box::new(DlogCommitmentOpen {
            public_share,
            blind_factor,
        }))
    }
}

impl EcdsaSeDe for ElgamalCipher {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.c1).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.c2).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let c1: GE = *EcdsaSeDe::deserialize(&msg[0..64].to_owned()).unwrap();
        let c2: GE = *EcdsaSeDe::deserialize(&msg[64..msg.len()].to_owned()).unwrap();
        Ok(Box::new(ElgamalCipher { c1, c2 }))
    }
}

impl EcdsaSeDe for MulPromiseCipher {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.ec_cipher).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.cl_cipher).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let ec_cipher = *EcdsaSeDe::deserialize(&msg[0..128].to_owned()).unwrap();
        let cl_cipher = *EcdsaSeDe::deserialize(&msg[128..msg.len()].to_owned()).unwrap();
        Ok(Box::new(MulPromiseCipher {
            ec_cipher,
            cl_cipher,
        }))
    }
}

impl EcdsaSeDe for MulPromiseState {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.cipher).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.ec_pub_key).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.cl_pub_key.0).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let cipher: MulPromiseCipher = *EcdsaSeDe::deserialize(&msg[0..796].to_owned()).unwrap();
        let ec_pub_key: GE = *EcdsaSeDe::deserialize(&msg[796..860].to_owned()).unwrap();
        let cl_pub_key: PK = PK(*EcdsaSeDe::deserialize(&msg[860..msg.len()].to_owned()).unwrap());
        Ok(Box::new(MulPromiseState {
            cipher,
            ec_pub_key,
            cl_pub_key,
        }))
    }
}

impl EcdsaSeDe for MulPromiseProof {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.A1).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.A2).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.a1).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.a2).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.z1).unwrap());
        let mut vec1 = EcdsaSeDe::serialize(&self.z2).unwrap();
        if vec1.len() < 162 {
            let mut vec2 = vec![0; 162 - vec1.len()];
            vec2.extend_from_slice(&vec1);
            vec1 = vec2;
        }
        vec.append(&mut vec1);
        vec.append(&mut EcdsaSeDe::serialize(&self.zm).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let a_big_1: GE = *EcdsaSeDe::deserialize(&msg[0..64].to_owned()).unwrap();
        let a_big_2: GE = *EcdsaSeDe::deserialize(&msg[64..128].to_owned()).unwrap();
        let a1: GmpClassGroup = *EcdsaSeDe::deserialize(&msg[128..462].to_owned()).unwrap();
        let a2: GmpClassGroup = *EcdsaSeDe::deserialize(&msg[462..796].to_owned()).unwrap();
        let z1: FE = *EcdsaSeDe::deserialize(&msg[796..828].to_owned()).unwrap();
        let z2: Mpz = *EcdsaSeDe::deserialize(&msg[828..990].to_owned()).unwrap();
        let zm: FE = *EcdsaSeDe::deserialize(&msg[990..msg.len()].to_owned()).unwrap();
        Ok(Box::new(MulPromiseProof {
            A1: a_big_1,
            A2: a_big_2,
            a1,
            a2,
            z1,
            z2,
            zm,
        }))
    }
}

impl EcdsaSeDe for HomoELGamalProof<CU, sha2::Sha256> {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.T).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.A3).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.z1).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.z2).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let t: GE = *EcdsaSeDe::deserialize(&msg[0..64].to_owned()).unwrap();
        let a3: GE = *EcdsaSeDe::deserialize(&msg[64..128].to_owned()).unwrap();
        let z1: FE = *EcdsaSeDe::deserialize(&msg[128..160].to_owned()).unwrap();
        let z2: FE = *EcdsaSeDe::deserialize(&msg[160..msg.len()].to_owned()).unwrap();
        Ok(Box::new(HomoELGamalProof::<CU, sha2::Sha256> {
            T: t,
            A3: a3,
            z1,
            z2,
            hash_choice: HashChoice::new(),
        }))
    }
}

#[test]
fn test_box() {
    use anyhow::format_err;
    let a = BigInt::from_bytes(&vec![21; 33]);
    let b = a.to_bytes();
    let c = bincode::serialize(&a)
        .map_err(|why| format_err!("bincode serialize error: {}", why))
        .unwrap();
    println!("b = {}", b.len());
    println!("c = {}", c.len());
}

#[test]
fn test_gmp() {
    let a = CLGroup::new_1827();
    println!("a = {:?}", a);
    let mut c = a.gq;
    c.pow(Mpz::from_str_radix("123456", 10).unwrap());
    println!("c = {:?}", c);
}
