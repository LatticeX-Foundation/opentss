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
use crate::utilities::error::MulEcdsaError;
use crate::{FE, GE};
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Point, Scalar};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::ops::Add;

// This part gives an ecnryption algorithm. And also gives a knowledge proof for elegmal ciphertexts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElgamalCipher {
    pub c1: GE,
    pub c2: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElgamalProof {
    pub a1: GE,
    pub a2: GE,
    pub z1: FE,
    pub z2: FE,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElgamalWit {
    pub x: FE,
    pub r: FE,
}

impl ElgamalCipher {
    pub fn encrypt(p_key: &GE, x: &FE) -> (Self, FE) {
        let base = Point::generator();
        let r: FE = Scalar::random();
        let c1 = base * &r;
        let hr = p_key * &r;
        let gx = base * x;
        let c2 = hr + gx;
        (ElgamalCipher { c1, c2 }, r)
    }
    pub fn encrypt_with_determained_randomness(p_key: &GE, wit: &ElgamalWit) -> Self {
        let base = Point::generator();
        let c1 = base * &wit.r;
        let hr = p_key * &wit.r;
        let gx = base * &wit.x;
        let c2 = hr + gx;
        ElgamalCipher { c1, c2 }
    }
}

impl Add for ElgamalCipher {
    type Output = ElgamalCipher;

    fn add(self, rhs: ElgamalCipher) -> ElgamalCipher {
        ElgamalCipher {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl ElgamalProof {
    pub fn prove(cipher: &ElgamalCipher, p_key: &GE, wit: &ElgamalWit) -> Self {
        let base: GE = GE::generator().to_point();
        let s1: FE = FE::random();
        let s2: FE = FE::random();
        let a1 = base.clone() * s1.clone();
        let a21 = p_key * &s1;
        let a22 = base * s2.clone();
        let a2 = a21 + a22;
        let e = Sha256::new()
            .chain_points([p_key, &cipher.c1, &cipher.c2, &a1, &a2])
            .result_scalar();

        let z1 = if wit.r.clone() != FE::zero() {
            s1 + wit.r.clone() * e.clone()
        } else {
            s1
        };

        // check that if x=0.
        let z2 = s2 + wit.x.clone() * e;
        ElgamalProof { a1, a2, z1, z2 }
    }
    pub fn verify(&self, cipher: &ElgamalCipher, p_key: &GE) -> Result<(), MulEcdsaError> {
        let e = Sha256::new()
            .chain_points([p_key, &cipher.c1, &cipher.c2, &self.a1, &self.a2])
            .result_scalar();

        let base: GE = GE::generator().to_point();
        let gz1 = base.clone() * self.z1.clone();
        let rcheck = cipher.c1.clone() * e.clone() + self.a1.clone();
        let hz1gz2 = p_key * &self.z1 + base * self.z2.clone();
        let xcheck = cipher.c2.clone() * e + self.a2.clone();
        if gz1 == rcheck && hz1gz2 == xcheck {
            Ok(())
        } else {
            Err(MulEcdsaError::VrfyElgamalProofFailed)
        }
    }
}

impl ElgamalWit {
    pub fn new_random() -> Self {
        Self {
            x: Scalar::random(),
            r: Scalar::random(),
        }
    }
}

#[test]
fn elgamal_test() {
    use super::eckeypair::EcKeyPair;
    let keypair = EcKeyPair::new();
    let witness = ElgamalWit::new_random();
    let cipher =
        ElgamalCipher::encrypt_with_determained_randomness(&keypair.public_share, &witness);
    let proof = ElgamalProof::prove(&cipher, &keypair.public_share, &witness);
    proof.verify(&cipher, &keypair.public_share).unwrap();
}
