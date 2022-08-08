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
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_BITS;
use crate::{CU, GE};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommitment {
    pub commitment: BigInt,
    pub open: DlogCommitmentOpen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommitmentOpen {
    pub public_share: GE,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLComZK {
    pub commitments: DLCommitments,
    pub witness: CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLCommitments {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof<CU, sha2::Sha256>,
}

impl DlogCommitment {
    pub fn new(public_share: &GE) -> Self {
        let blind_factor = BigInt::sample(SECURITY_BITS);
        let commitment =
            HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(&public_share.to_bytes(true)),
                &blind_factor,
            );

        Self {
            commitment,
            open: DlogCommitmentOpen {
                public_share: public_share.clone(),
                blind_factor,
            },
        }
    }

    pub fn verify(&self) -> Result<(), MulEcdsaError> {
        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&self.open.public_share.to_bytes(true)),
            &self.open.blind_factor,
        ) != self.commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        Ok(())
    }

    pub fn verify_dlog(
        commitment: &BigInt,
        open: &DlogCommitmentOpen,
    ) -> Result<(), MulEcdsaError> {
        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&open.public_share.to_bytes(true)),
            &open.blind_factor,
        ) != *commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        Ok(())
    }

    pub fn get_public_share(&self) -> GE {
        self.open.public_share.clone()
    }
}

impl DLComZK {
    pub fn new(keypair: &EcKeyPair) -> Self {
        let d_log_proof = DLogProof::<CU, sha2::Sha256>::prove(keypair.get_secret_key());
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment =
            HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(&keypair.get_public_key().to_bytes(true)),
                &pk_commitment_blind_factor,
            );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment =
            HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(&d_log_proof.pk_t_rand_commitment.to_bytes(true)),
                &zk_pok_blind_factor,
            );

        let commitments = DLCommitments {
            pk_commitment,
            zk_pok_commitment,
        };

        let witness = CommWitness {
            pk_commitment_blind_factor,
            zk_pok_blind_factor,
            public_share: keypair.get_public_key().clone(),
            d_log_proof,
        };

        Self {
            commitments,
            witness,
        }
    }

    pub fn verify_commitments_and_dlog_proof(&self) -> Result<(), MulEcdsaError> {
        // Verify the commitment of DL
        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&self.witness.public_share.to_bytes(true)),
            &self.witness.pk_commitment_blind_factor,
        ) != self.commitments.pk_commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        // Verify the commitment of proof
        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&self.witness.d_log_proof.pk_t_rand_commitment.to_bytes(true)),
            &self.witness.zk_pok_blind_factor,
        ) != self.commitments.zk_pok_commitment
        {
            return Err(MulEcdsaError::OpenCommZKFailed);
        }

        // Verify DL proof
        DLogProof::verify(&self.witness.d_log_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(())
    }

    pub fn verify(commitment: &DLCommitments, witness: &CommWitness) -> Result<(), MulEcdsaError> {
        // Verify the commitment of DL
        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&witness.public_share.to_bytes(true)),
            &witness.pk_commitment_blind_factor,
        ) != commitment.pk_commitment
        {
            return Err(MulEcdsaError::OpenDLCommFailed);
        }

        // Verify the commitment of proof
        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(&witness.d_log_proof.pk_t_rand_commitment.to_bytes(true)),
            &witness.zk_pok_blind_factor,
        ) != commitment.zk_pok_commitment
        {
            return Err(MulEcdsaError::OpenCommZKFailed);
        }

        // Verify DL proof
        DLogProof::verify(&witness.d_log_proof).map_err(|_| MulEcdsaError::VrfyDlogFailed)?;
        Ok(())
    }

    pub fn get_public_share(&self) -> GE {
        self.witness.public_share.clone()
    }
}

impl CommWitness {
    pub fn get_public_key(&self) -> &GE {
        &self.public_share
    }
}

impl Default for DLCommitments {
    fn default() -> DLCommitments {
        DLCommitments {
            pk_commitment: BigInt::zero(),
            zk_pok_commitment: BigInt::zero(),
        }
    }
}

#[test]
fn dl_com_zk_test() {
    let keypair = EcKeyPair::new();

    let dl_com_zk = DLComZK::new(&keypair);

    dl_com_zk.verify_commitments_and_dlog_proof().unwrap();
}
