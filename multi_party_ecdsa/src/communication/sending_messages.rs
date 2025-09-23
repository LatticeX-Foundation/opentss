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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SendingMessages {
    NormalMessage(String, Vec<u8>),       // (to, message)
    P2pMessage(HashMap<String, Vec<u8>>), // (to, message)
    SubsetMessage(Vec<u8>),               // (message), send according to subset
    BroadcastMessage(Vec<u8>),            // (message), send to all participants
    EmptyMsg,
    KeyGenSuccessWithResult(String),
    SignOfflineSuccessWithResult(String),
    SignOnlineSuccessWithResult(String),
    ReshareKeySuccessWithResult(String),
}
