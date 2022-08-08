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
use curv::arithmetic::traits::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    pub r: FE,
    pub recid: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureX {
    pub s: String,
    pub r: String,
    pub recid: u8,
}

impl Signature {
    pub fn verify(&self, pubkey: &GE, message: &FE) -> Result<(), MulEcdsaError> {
        let q = FE::group_order();

        let s_inv_fe = self.s.invert().unwrap();
        let u1 = GE::generator() * (message * &s_inv_fe);
        let u2 = pubkey * (&self.r * &s_inv_fe);

        // second condition is against malleability
        let u1_plus_u2 = (u1 + u2).x_coord().unwrap().mod_floor(q);

        if self.r.to_bigint() == u1_plus_u2 && self.s.to_bigint() < q - self.s.to_bigint() {
            Ok(())
        } else {
            return Err(MulEcdsaError::VrfyMultiECDSAFailed);
        }
    }
}
