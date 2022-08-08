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
use classgroup::ClassGroup;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClKeyPair {
    pub cl_pub_key: PK,
    pub cl_priv_key: SK,
}

impl ClKeyPair {
    pub fn new(group: &CLGroup) -> Self {
        let (cl_priv_key, cl_pub_key) = group.keygen();
        Self {
            cl_pub_key,
            cl_priv_key,
        }
    }

    pub fn from_sk(sk: SK, group: &CLGroup) -> Self {
        let cl_pub_key = group.pk_for_sk(sk.clone());
        Self {
            cl_pub_key,
            cl_priv_key: sk,
        }
    }

    pub fn update_pk_exp_p(&mut self) {
        let mut new_pk = self.cl_pub_key.0.clone();
        new_pk.pow(q());
        self.cl_pub_key = PK(new_pk);
    }

    pub fn get_public_key(&self) -> &PK {
        &self.cl_pub_key
    }

    pub fn get_secret_key(&self) -> &SK {
        &self.cl_priv_key
    }
}
