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
use crate::protocols::multi_party::dmz21::common::*;
use crate::utilities::class_group::*;
use crate::utilities::dl_com_zk::*;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::promise_sigma_multi::{PromiseProof, PromiseState};
use crate::utilities::serialize::EcdsaSeDe;
use crate::utilities::vss::Vss;
use classgroup::gmp_classgroup::*;
use curv::arithmetic::Converter;
use curv::arithmetic::One;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MultiKeyGenMessage {
    PhaseOneTwoMsg(KeyGenPhaseOneTwoMsg),
    PhaseThreeMsg(KeyGenPhaseThreeMsg),
    PhaseFourMsg(KeyGenPhaseFourMsg),
    PhaseFiveMsg(KeyGenPhaseFiveMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MultiSignMessage {
    PhaseOneMsg(SignPhaseOneMsg),
    PhaseTwoMsg(SignPhaseTwoMsg),
    PhaseThreeMsg(SignPhaseThreeMsg),
    PhaseFourMsg(SignPhaseFourMsg),
    PhaseFiveStepOneMsg(SignPhaseFiveStepOneMsg),
    PhaseFiveStepTwoMsg(SignPhaseFiveStepTwoMsg),
    PhaseFiveStepFourMsg(SignPhaseFiveStepFourMsg),
    PhaseFiveStepFiveMsg(SignPhaseFiveStepFiveMsg),
    PhaseFiveStepSevenMsg(SignPhaseFiveStepSevenMsg),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyGenPhaseOneTwoMsg {
    pub h_caret: PK,
    pub h: PK,
    pub ec_pk: GE,
    pub gp: GmpClassGroup,
    pub commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseThreeMsg {
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseFourMsg {
    pub vss_scheme: Vss,
    pub secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenPhaseFiveMsg {
    pub dl_proof: DLogProof<CU, sha2::Sha256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseOneMsg {
    pub commitment: BigInt,
    pub promise_state: PromiseState,
    pub proof: PromiseProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseTwoMsg {
    pub homocipher: Ciphertext,
    pub homocipher_plus: Ciphertext,
    pub t_p: FE,
    pub t_p_plus: FE,
    pub b: GE,
}

impl SignPhaseTwoMsg {
    pub fn new() -> Self {
        let c1 = GmpClassGroup::default();
        let c2 = GmpClassGroup::default();
        let homocipher = Ciphertext {
            c1: c1.clone(),
            c2: c2.clone(),
        };
        let homocipher_plus = Ciphertext { c1, c2 };
        SignPhaseTwoMsg {
            homocipher,
            homocipher_plus,
            t_p: FE::random(),
            t_p_plus: FE::random(),
            b: GE::generator().to_point(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseThreeMsg {
    pub delta: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFourMsg {
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepOneMsg {
    pub commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepTwoMsg {
    pub v_i: GE,
    pub a_i: GE,
    pub b_i: GE,
    pub blind: BigInt,
    pub dl_proof: DLogProof<CU, sha2::Sha256>,
    pub proof: HomoELGamalProof<CU, sha2::Sha256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepFourMsg {
    pub commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepFiveMsg {
    pub blind: BigInt,
    pub u_i: GE,
    pub t_i: GE,
}

impl SignPhaseFiveStepFiveMsg {
    pub fn new() -> Self {
        Self {
            blind: BigInt::one(),
            u_i: GE::generator().to_point(),
            t_i: GE::generator().to_point(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignPhaseFiveStepSevenMsg {
    pub s_i: FE,
}

impl EcdsaSeDe for KeyGenPhaseOneTwoMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.h_caret.0).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.h.0).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.ec_pk).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.gp).unwrap());
        vec.append(&mut self.commitment.to_bytes());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let h_caret: PK = PK(*EcdsaSeDe::deserialize(&msg[0..334].to_owned()).unwrap());
        let h: PK = PK(*EcdsaSeDe::deserialize(&msg[334..668].to_owned()).unwrap());
        let ec_pk: GE = *EcdsaSeDe::deserialize(&msg[668..732].to_owned()).unwrap();
        let gp: GmpClassGroup = *EcdsaSeDe::deserialize(&msg[732..1066].to_owned()).unwrap();
        let commitment: BigInt = BigInt::from_bytes(&msg[1066..msg.len()]);
        Ok(Box::new(KeyGenPhaseOneTwoMsg {
            h_caret,
            h,
            ec_pk,
            gp,
            commitment,
        }))
    }
}

impl EcdsaSeDe for KeyGenPhaseThreeMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        Ok(EcdsaSeDe::serialize(&self.open).unwrap())
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let open: DlogCommitmentOpen = *EcdsaSeDe::deserialize(&msg).unwrap();
        Ok(Box::new(KeyGenPhaseThreeMsg { open }))
    }
}

impl EcdsaSeDe for KeyGenPhaseFiveMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        Ok(EcdsaSeDe::serialize(&self.dl_proof).unwrap())
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let dl_proof: DLogProof<CU, sha2::Sha256> = *EcdsaSeDe::deserialize(&msg).unwrap();
        Ok(Box::new(KeyGenPhaseFiveMsg { dl_proof }))
    }
}

impl EcdsaSeDe for SignPhaseOneMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.commitment.to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        vec.append(&mut EcdsaSeDe::serialize(&self.promise_state).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.proof).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let commitment: BigInt = BigInt::from_bytes(&msg[0..32]);
        let promise_state: PromiseState =
            *EcdsaSeDe::deserialize(&msg[32..1226].to_owned()).unwrap();
        let proof: PromiseProof =
            *EcdsaSeDe::deserialize(&msg[1226..msg.len()].to_owned()).unwrap();
        Ok(Box::new(SignPhaseOneMsg {
            commitment,
            promise_state,
            proof,
        }))
    }
}

impl EcdsaSeDe for SignPhaseTwoMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.homocipher).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.homocipher_plus).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.t_p).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.t_p_plus).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.b).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let homocipher: Ciphertext = *EcdsaSeDe::deserialize(&msg[0..668].to_owned()).unwrap();
        let homocipher_plus: Ciphertext =
            *EcdsaSeDe::deserialize(&msg[668..1336].to_owned()).unwrap();
        let t_p: FE = *EcdsaSeDe::deserialize(&msg[1336..1368].to_owned()).unwrap();
        let t_p_plus: FE = *EcdsaSeDe::deserialize(&msg[1368..1400].to_owned()).unwrap();
        let b: GE = *EcdsaSeDe::deserialize(&msg[1400..msg.len()].to_owned()).unwrap();
        Ok(Box::new(SignPhaseTwoMsg {
            homocipher,
            homocipher_plus,
            t_p,
            t_p_plus,
            b,
        }))
    }
}

impl EcdsaSeDe for SignPhaseThreeMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        Ok(EcdsaSeDe::serialize(&self.delta).unwrap())
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let delta: FE = *EcdsaSeDe::deserialize(&msg).unwrap();
        Ok(Box::new(SignPhaseThreeMsg { delta }))
    }
}

impl EcdsaSeDe for SignPhaseFourMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        Ok(EcdsaSeDe::serialize(&self.open).unwrap())
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let open: DlogCommitmentOpen = *EcdsaSeDe::deserialize(&msg).unwrap();
        Ok(Box::new(SignPhaseFourMsg { open }))
    }
}

impl EcdsaSeDe for SignPhaseFiveStepOneMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.commitment.to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let commitment = BigInt::from_bytes(&msg);
        Ok(Box::new(SignPhaseFiveStepOneMsg { commitment }))
    }
}

impl EcdsaSeDe for SignPhaseFiveStepTwoMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = EcdsaSeDe::serialize(&self.v_i).unwrap();
        vec.append(&mut EcdsaSeDe::serialize(&self.a_i).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.b_i).unwrap());
        let mut vec1 = self.blind.to_bytes();
        if vec1.len() < 32 {
            let mut vec2 = vec![0; 32 - vec1.len()];
            vec2.extend_from_slice(&vec1);
            vec1 = vec2;
        }
        vec.append(&mut vec1);
        vec.append(&mut EcdsaSeDe::serialize(&self.dl_proof).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.proof).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let v_i: GE = *EcdsaSeDe::deserialize(&msg[0..64].to_owned()).unwrap();
        let a_i: GE = *EcdsaSeDe::deserialize(&msg[64..128].to_owned()).unwrap();
        let b_i: GE = *EcdsaSeDe::deserialize(&msg[128..192].to_owned()).unwrap();
        let blind = BigInt::from_bytes(&msg[192..224]);
        let dl_proof: DLogProof<CU, sha2::Sha256> =
            *EcdsaSeDe::deserialize(&msg[224..384].to_owned()).unwrap();
        let proof: HomoELGamalProof<CU, sha2::Sha256> =
            *EcdsaSeDe::deserialize(&msg[384..msg.len()].to_owned()).unwrap();
        Ok(Box::new(SignPhaseFiveStepTwoMsg {
            v_i,
            a_i,
            b_i,
            blind,
            dl_proof,
            proof,
        }))
    }
}

impl EcdsaSeDe for SignPhaseFiveStepFourMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        Ok(self.commitment.to_bytes())
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let commitment = BigInt::from_bytes(&msg);
        Ok(Box::new(SignPhaseFiveStepFourMsg { commitment }))
    }
}

impl EcdsaSeDe for SignPhaseFiveStepFiveMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        let mut vec = self.blind.to_bytes();
        if vec.len() < 32 {
            let mut vec1 = vec![0; 32 - vec.len()];
            vec1.extend_from_slice(&vec);
            vec = vec1;
        }
        vec.append(&mut EcdsaSeDe::serialize(&self.u_i).unwrap());
        vec.append(&mut EcdsaSeDe::serialize(&self.t_i).unwrap());
        Ok(vec)
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let blind = BigInt::from_bytes(&msg[0..32]);
        let u_i: GE = *EcdsaSeDe::deserialize(&msg[32..96].to_owned()).unwrap();
        let t_i: GE = *EcdsaSeDe::deserialize(&msg[96..160].to_owned()).unwrap();
        Ok(Box::new(SignPhaseFiveStepFiveMsg { blind, u_i, t_i }))
    }
}

impl EcdsaSeDe for SignPhaseFiveStepSevenMsg {
    fn serialize(&self) -> Result<Vec<u8>, MulEcdsaError> {
        Ok(EcdsaSeDe::serialize(&self.s_i).unwrap())
    }
    fn deserialize(msg: &Vec<u8>) -> Result<Box<Self>, MulEcdsaError> {
        let s_i: FE = *EcdsaSeDe::deserialize(&msg).unwrap();
        Ok(Box::new(SignPhaseFiveStepSevenMsg { s_i }))
    }
}
