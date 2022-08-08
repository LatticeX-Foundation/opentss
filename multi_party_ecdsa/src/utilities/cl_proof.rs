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
use crate::utilities::class_group::*;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_PARAMETER;
use crate::FE;
use classgroup::gmp::mpz::Mpz;
use classgroup::gmp_classgroup::*;
use classgroup::ClassGroup;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::BigInt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLState {
    pub cipher: Ciphertext,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLWit {
    pub x: FE,
    pub r: SK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLProof {
    pub t1: GmpClassGroup,
    pub t2: GmpClassGroup,
    pub u1: Mpz,
    pub u2: Mpz,
}

impl CLProof {
    pub fn prove(group: &CLGroup, witness: CLWit, statement: CLState) -> Self {
        let r1 = BigInt::sample_below(
            &(&mpz_to_bigint(&group.stilde)
                * BigInt::from(2u32).pow(40)
                * BigInt::from(2u32).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2u32).pow(40)),
        );
        let r1_mpz = bigint_to_mpz(&r1);
        let r2_fe: FE = FE::random();
        let r2 = into_mpz(&r2_fe);
        let fr2 = expo_f(&q(), &group.gq.discriminant(), &r2);
        let mut pkr1 = statement.cl_pub_key.0.clone();
        pkr1.pow(r1_mpz.clone());
        let t2 = fr2 * pkr1;
        let mut t1 = group.gq.clone();
        t1.pow(r1_mpz.clone());
        let k = Self::challenge(
            &statement.cl_pub_key,
            t1.clone(),
            t2.clone(),
            &statement.cipher,
        );
        let u1 = r1_mpz + &bigint_to_mpz(&k) * &witness.r.0;
        let u2 = BigInt::mod_add(
            &mpz_to_bigint(&r2),
            &(&k * witness.x.to_bigint()),
            &FE::group_order(),
        );

        Self {
            t1,
            t2,
            u1,
            u2: bigint_to_mpz(&u2),
        }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    pub fn challenge(
        public_key: &PK,
        t1: GmpClassGroup,
        t2: GmpClassGroup,
        ciphertext: &Ciphertext,
    ) -> BigInt {
        let hash256 = Sha256::new()
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            .chain_bigint(&BigInt::from_bytes(ciphertext.c1.to_bytes().as_ref()))
            .chain_bigint(&BigInt::from_bytes(ciphertext.c2.to_bytes().as_ref()))
            .chain_bigint(&BigInt::from_bytes(public_key.0.to_bytes().as_ref()))
            // hash Sigma protocol commitments
            .chain_bigint(&BigInt::from_bytes(t1.to_bytes().as_ref()))
            .chain_bigint(&BigInt::from_bytes(t2.to_bytes().as_ref()))
            .result_bigint();

        let hash128 = &BigInt::to_bytes(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from_bytes(hash128)
    }

    pub fn verify(&self, group: &CLGroup, statement: CLState) -> Result<(), MulEcdsaError> {
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(
            &statement.cl_pub_key,
            self.t1.clone(),
            self.t2.clone(),
            &statement.cipher,
        );

        let sample_size = &mpz_to_bigint(&group.stilde)
            * (BigInt::from(2u32).pow(40))
            * BigInt::from(2u32).pow(SECURITY_PARAMETER as u32)
            * (BigInt::from(2u32).pow(40) + BigInt::one());

        // length test u1:
        if &self.u1 > &bigint_to_mpz(&sample_size) || &self.u1 < &Mpz::zero() {
            flag = false;
        }
        // length test u2:
        if &self.u2 > &q() || &self.u2 < &Mpz::zero() {
            flag = false;
        }

        let mut c1k = statement.cipher.c1;
        c1k.pow(bigint_to_mpz(&k));
        let t1c1k = self.t1.clone() * c1k;
        let mut gqu1 = group.gq.clone();
        gqu1.pow(self.u1.clone());
        if t1c1k != gqu1 {
            flag = false;
        };

        let mut pku1 = statement.cl_pub_key.0;
        pku1.pow(self.u1.clone());
        let fu2 = expo_f(&q(), &group.gq.discriminant(), &self.u2);
        let mut c2k = statement.cipher.c2;
        c2k.pow(bigint_to_mpz(&k));
        let t2c2k = self.t2.clone() * c2k;
        let pku1fu2 = pku1 * fu2;
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(MulEcdsaError::VrfyCLProofFailed),
        }
    }
}
