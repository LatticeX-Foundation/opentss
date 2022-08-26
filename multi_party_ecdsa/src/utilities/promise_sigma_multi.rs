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
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::utilities::class_group::Ciphertext as CLCipher;
use crate::utilities::class_group::*;
use crate::utilities::elgamal::ElgamalCipher;
use crate::utilities::error::MulEcdsaError;
use crate::utilities::SECURITY_PARAMETER;
use crate::{FE, GE};
use classgroup::gmp::mpz::Mpz;
use classgroup::gmp_classgroup::*;
use classgroup::ClassGroup;
use curv::arithmetic::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Point, Scalar};
use curv::BigInt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseCipher {
    pub ec_cipher: ElgamalCipher,
    pub cl_cipher: CLCipher,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseProof {
    pub A1: GE,
    pub A2: GE,
    pub a1: GmpClassGroup,
    pub a2: GmpClassGroup,
    pub z1: FE,
    pub z2: Mpz,
    pub zm: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseState {
    pub cipher: PromiseCipher,
    pub ec_pub_key: GE,
    pub cl_pub_key: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromiseWit {
    pub m: FE,
    pub r1: FE,
    pub r2: SK,
}

impl PromiseCipher {
    pub fn encrypt(group: &CLGroup, cl_pub_key: &PK, ec_pub_key: &GE, m: &FE) -> (Self, FE, SK) {
        let (ec_cipher, r1) = ElgamalCipher::encrypt(ec_pub_key, m);
        let (cl_cipher, r2) = CLGroup::encrypt(group, cl_pub_key, m);

        (
            Self {
                ec_cipher,
                cl_cipher,
            },
            r1,
            r2,
        )
    }

    pub fn decrypt(&self, group: &CLGroup, sk: &SK) -> FE {
        CLGroup::decrypt(group, sk, &self.cl_cipher)
    }
}

impl PromiseProof {
    pub fn prove(group: &CLGroup, stat: &PromiseState, wit: &PromiseWit) -> Self {
        // First round
        let G = Point::generator();
        let P = stat.ec_pub_key.clone();

        let s1: FE = FE::random();
        let s2 = BigInt::sample_below(
            &(&mpz_to_bigint(&group.stilde)
                * BigInt::from(2u32).pow(40)
                * BigInt::from(2u32).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2u32).pow(40)),
        );
        let sm = FE::random();

        let A1 = G * &s1;
        let A2 = G * &sm + &P * &s1;
        let mut a1 = group.gq.clone();
        let mut pkr1 = stat.cl_pub_key.0.clone();
        crossbeam::scope(|thread| {
            thread.spawn(|_| {
                a1.pow(bigint_to_mpz(&s2));
            });
            thread.spawn(|_| {
                pkr1.pow(bigint_to_mpz(&s2));
            });
        })
        .unwrap();

        let fr = expo_f(&q(), &group.gq.discriminant(), &into_mpz(&sm));
        let a2 = fr * pkr1;

        // Second round: get challenge
        let e = Self::challenge(&stat, &A1, &A2, &a1, &a2);

        // Third round
        let z11 = BigInt::mod_add(
            &s1.to_bigint(),
            &(&e * &wit.r1.to_bigint()),
            &FE::group_order(),
        );
        let z1 = Scalar::from(&z11);
        let z2 = bigint_to_mpz(&s2) + &bigint_to_mpz(&e) * &wit.r2.0;
        let zm1 = BigInt::mod_add(
            &sm.to_bigint(),
            &(&e * &wit.m.to_bigint()),
            &FE::group_order(),
        );
        let zm = Scalar::from(&zm1);

        Self {
            A1,
            A2,
            a1,
            a2,
            z1,
            z2,
            zm,
        }
    }

    pub fn challenge(
        state: &PromiseState,
        A1: &GE,
        A2: &GE,
        a1: &GmpClassGroup,
        a2: &GmpClassGroup,
    ) -> BigInt {
        let hash256 = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(A1.to_bytes(true).as_ref()))
            .chain_bigint(&BigInt::from_bytes(A2.to_bytes(true).as_ref()))
            .chain_bigint(&BigInt::from_bytes(&a1.to_bytes()))
            .chain_bigint(&BigInt::from_bytes(&a2.to_bytes()))
            .chain_bigint(&BigInt::from_bytes(&state.cipher.cl_cipher.c1.to_bytes()))
            .chain_bigint(&BigInt::from_bytes(&state.cipher.cl_cipher.c2.to_bytes()))
            .chain_bigint(&BigInt::from_bytes(
                state.cipher.ec_cipher.c1.to_bytes(true).as_ref(),
            ))
            .chain_bigint(&BigInt::from_bytes(
                state.cipher.ec_cipher.c2.to_bytes(true).as_ref(),
            ))
            .result_bigint();

        let hash128 = &BigInt::to_bytes(&hash256)[..SECURITY_PARAMETER / 8];
        BigInt::from_bytes(hash128)
    }

    pub fn verify(&self, group: &CLGroup, stat: &PromiseState) -> Result<(), MulEcdsaError> {
        let (C1, C2, c1, c2) = (
            &stat.cipher.ec_cipher.c1,
            &stat.cipher.ec_cipher.c2,
            &stat.cipher.cl_cipher.c1,
            &stat.cipher.cl_cipher.c2,
        );
        let G = Point::generator();
        let P = &stat.ec_pub_key;
        let cl_pub_key = &stat.cl_pub_key;
        let e: BigInt = Self::challenge(&stat, &self.A1, &self.A2, &self.a1, &self.a2);
        let e_fe: FE = Scalar::from(&e);
        let r1_left = G * &self.z1;
        let r1_right = &self.A1 + &(C1 * &e_fe);
        let mut r2_left = group.gq.clone();
        let mut c1k = c1.clone();
        let mut pkz2 = cl_pub_key.0.clone();
        let mut c2k = c2.clone();

        crossbeam::scope(|thread| {
            thread.spawn(|_| {
                r2_left.pow(self.z2.clone());
                c1k.pow(bigint_to_mpz(&e));
            });
            thread.spawn(|_| {
                pkz2.pow(self.z2.clone());
                c2k.pow(bigint_to_mpz(&e));
            });
        })
        .unwrap();

        let r2_right = self.a1.clone() * c1k;
        let m_ec_left = G * &self.zm + P * &self.z1;
        let m_ec_right = &self.A2 + &(C2 * &e_fe);
        let fz3 = expo_f(&q(), &group.gq.discriminant(), &into_mpz(&self.zm));
        let m_cl_left = pkz2 * fz3;
        let m_cl_right = self.a2.clone() * c2k;
        if r1_left == r1_right
            && r2_left == r2_right
            && m_cl_left == m_cl_right
            && m_ec_left == m_ec_right
        {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyPromiseFailed)
        }
    }
}
