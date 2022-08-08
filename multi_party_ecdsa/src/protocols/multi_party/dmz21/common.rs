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
pub use crate::{CU, FE, GE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

///VSS parameters
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Parameters {
    pub threshold: usize,   // t
    pub share_count: usize, // n
}

/// Public part of keygen result
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub pk: GE,
    pub share_pks: HashMap<String, GE>,
}

/// Private part of keygen result
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateKey {
    pub cl_sk: SK,
    pub ec_sk: FE,
    pub share_sk: FE,
}

/// Keygen result
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DMZKey {
    pub index: String,
    pub participants: Vec<String>,
    pub pubkey: PublicKey,
    pub privkey: PrivateKey,
}

/// Public part of keygen result
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyX {
    pub pk: Vec<String>,                         // [x, y]
    pub share_pks: HashMap<String, Vec<String>>, // partyid => [share_pk.x, share_pk.y]
}

/// Private part of keygen result
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateKeyX {
    pub cl_sk: SK,
    pub ec_sk: String,
    pub share_sk: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DMZKeyX {
    pub index: String,
    pub participants: Vec<String>,
    pub pubkey: PublicKeyX,
    pub privkey: PrivateKeyX,
}
