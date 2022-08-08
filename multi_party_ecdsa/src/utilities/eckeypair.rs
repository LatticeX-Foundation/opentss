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
use crate::{FE, GE};
use curv::elliptic::curves::{Point, Scalar};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    pub secret_share: FE,
}

impl EcKeyPair {
    pub fn new() -> Self {
        let base = Point::generator();
        let secret_share: FE = Scalar::random();
        let public_share = base * &secret_share;
        Self {
            secret_share,
            public_share,
        }
    }

    pub fn from_sk(sk: FE) -> Self {
        let base = Point::generator();
        let public_share = base * &sk;
        Self {
            secret_share: sk,
            public_share,
        }
    }

    pub fn get_public_key(&self) -> &GE {
        &self.public_share
    }

    pub fn get_secret_key(&self) -> &FE {
        &self.secret_share
    }
}
