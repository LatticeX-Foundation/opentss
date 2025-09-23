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
use crate::utilities::promise_sigma_multi::{PromiseProof, PromiseState};
use crate::utilities::vss::Vss;
use classgroup::gmp_classgroup::*;
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
    pub dl_proof: DLogProof<CU, sha2::Sha256>,
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


#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MultiReshareMessage {
    ReshareStartMessage(ReshareStartMessage),
    ResharePhaseMsg(ResharePhaseMsg),
    ReshareDLEQMsg(ReshareDLEQMsg),
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReshareStartMessage {
    pub new_party_ids: Vec<String>,
    pub new_threshold: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResharePhaseMsg {
    pub vss_scheme: Vss,
    pub secret_share: FE,
    pub public_signing_key: (String, String), // (x, y) coordinates as hex strings
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReshareDLEQMsg {
     pub dl_proof: DLogProof<CU, sha2::Sha256>,
}