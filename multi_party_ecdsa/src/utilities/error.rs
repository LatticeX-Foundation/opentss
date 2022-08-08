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
use thiserror::Error;

/// Represents errors.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum MulEcdsaError {
    #[error("Open dlcommitment failed")]
    OpenDLCommFailed,
    #[error("Open zk-pok commitment failed")]
    OpenCommZKFailed,
    #[error("Verify DLog failed")]
    VrfyDlogFailed,
    #[error("The size of zr excceeds sample size")]
    ZrExcceedSize,
    #[error("Verify promise sigma protocol failed")]
    VrfyPromiseFailed,
    #[error("The return of x_coor() in None")]
    XcoorNone,
    #[error("Verify multi-party ECDSA signature failed")]
    VrfyMultiECDSAFailed,
    #[error("Verify class group pk failed")]
    VrfyClassGroupFailed,
    #[error("Get index failed")]
    GetIndexFailed,
    #[error("Serialize failed ")]
    SerializeFailed,
    #[error("Verify VSS failed")]
    VrfyVSSFailed,
    #[error("To string failed")]
    ToStringFailed,
    #[error("From string failed")]
    FromStringFailed,
    #[error("Party numbers less than the value of threshold in multiparty ecdsa keygen")]
    PartyLessThanThreshold,
    #[error("Left not equal to Right")]
    LeftNotEqualRight,
    #[error("Verify multiparty ecdsa sign phase one message failed")]
    VrfySignPhaseOneMsgFailed,
    #[error("Handle multiparty ecdsa sign phase two message failed")]
    HandleSignPhaseTwoMsgFailed,
    #[error("Open general commitment failed")]
    OpenGeCommFailed,
    #[error("Verify HomoElGamal failed")]
    VrfyHomoElGamalFailed,
    #[error("Verify sum_a_t failed")]
    VrfySumatFailed,
    #[error("Compute delta sum msg in multiparty ecdsa sign phase two failed")]
    ComputeDeltaSumFailed,
    #[error("Verify ElgamalProof failed")]
    VrfyElgamalProofFailed,
    #[error("Verify CLEncProof failed")]
    VrfyClEncProofFailed,
    #[error("Verify CLDLProof Failed")]
    VrfyCLDLProofFailed,
    #[error("Verify CLProof Failed")]
    VrfyCLProofFailed,
    #[error("Not load keygen result")]
    VrfyPKFailed,
    #[error("verify update pk failed")]
    NotLoadKeyGenResult,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("From Hex Failed")]
    FromHexFailed,
    #[error("Generate Result Json String Failed")]
    GenerateJsonStringFailed,
    #[error("Missing message to sign")]
    MissingMsg,
    #[error("Invert a zero element")]
    InvertZero,
    #[error("General error")]
    GeneralError,
}
