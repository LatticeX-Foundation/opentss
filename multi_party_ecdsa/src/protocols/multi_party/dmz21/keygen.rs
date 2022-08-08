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
//! Implement keygen algorithm of multi-party ECDSA in dmz
use crate::communication::sending_messages::SendingMessages;
pub use crate::protocols::multi_party::dmz21::common::Parameters; // for compatibility
use crate::protocols::multi_party::dmz21::common::*;
use crate::protocols::multi_party::dmz21::message::*;
use crate::utilities::class_group::*;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::vss::*;
use anyhow::{anyhow, format_err};
use classgroup::gmp_classgroup::*;
use classgroup::ClassGroup;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// Messages of each round in keygen
#[derive(Clone, Debug)]
pub struct KeyGenMsgs {
    pub phase_one_two_msgs: HashMap<String, KeyGenPhaseOneTwoMsg>,
    pub phase_three_msgs: HashMap<String, KeyGenPhaseThreeMsg>,
    pub phase_four_vss_sending_msgs: HashMap<String, Vec<u8>>,
    pub phase_four_msgs: HashMap<String, KeyGenPhaseFourMsg>,
    pub phase_five_msgs: HashMap<String, KeyGenPhaseFiveMsg>,
}

/// Key generation struct
#[derive(Clone, Debug)]
pub struct KeyGenPhase {
    pub party_index: String,
    pub party_ids: Vec<String>,
    pub params: Parameters,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub h_caret: PK,
    pub private_signing_key: EcKeyPair,        // (u_i, u_iP)
    pub public_signing_key: GE,                // Q
    pub share_private_key: FE,                 // x_i
    pub share_public_key: HashMap<String, GE>, // X_i
    pub msgs: KeyGenMsgs,
    pub dlog_com: DlogCommitment,
    pub mutex: Arc<Mutex<usize>>,
}

impl KeyGenMsgs {
    pub fn new() -> Self {
        Self {
            phase_one_two_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_vss_sending_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_five_msgs: HashMap::new(),
        }
    }

    pub fn clean(&mut self) {
        self.phase_one_two_msgs.clear();
        self.phase_three_msgs.clear();
        self.phase_four_vss_sending_msgs.clear();
        self.phase_four_msgs.clear();
        self.phase_five_msgs.clear();
    }
}

impl KeyGenPhase {
    /// partyid: The party id(index). Hex-string. (0, the modulus of the curve)
    /// params: t,n. t>0, n>t.
    /// party_ids: The list of parties whose size is equal to params.n.
    pub fn new(
        partyid: String,
        params: Parameters,
        party_ids: &Option<Vec<String>>,
    ) -> Result<Self, anyhow::Error> {
        // todo: remove the Option for party_ids in the future
        if *party_ids == None {
            return Err(anyhow!("party_ids is none"));
        }

        let mutex = Arc::new(Mutex::new(0));
        // Generate cl keypair
        let mut cl_keypair = ClKeyPair::new(&GROUP_1827);
        let h_caret = cl_keypair.get_public_key().clone();
        cl_keypair.update_pk_exp_p();
        // Generate elgamal keypair
        let ec_keypair = EcKeyPair::new();
        // Generate signing key pair
        let private_signing_key = EcKeyPair::new();
        // Init public key, compute later
        let public_signing_key = private_signing_key.get_public_key().clone();
        let mut msgs = KeyGenMsgs::new();
        // Generate dl com
        let dlog_com = DlogCommitment::new(&public_signing_key);

        // Generate phase four msg, vss
        let share_private_key = KeyGenPhase::phase_four_generate_vss(
            &mut msgs,
            partyid.clone(),
            params.threshold,
            params.share_count,
            private_signing_key.get_secret_key(),
            (*party_ids).clone(),
        )?;
        Ok(Self {
            party_index: partyid.clone(),
            party_ids: (*party_ids).clone().unwrap(),
            params,
            ec_keypair,
            cl_keypair,
            h_caret,
            private_signing_key,
            public_signing_key,
            share_private_key, // Init share private key, compute later.
            share_public_key: HashMap::new(),
            msgs,
            dlog_com,
            mutex,
        })
    }

    fn verify_phase_one_msg(
        &self,
        h_caret: &PK,
        h: &PK,
        gp: &GmpClassGroup,
    ) -> Result<(), anyhow::Error> {
        let mut h_ret = h_caret.0.clone();
        h_ret.pow(q());
        if h_ret != h.0 || *gp != GROUP_UPDATE_1827.gq {
            return Err(anyhow!(
                "Verify phase one msg failed in keygen phase onetwo"
            ));
        }
        Ok(())
    }

    fn handle_phase_three_msg(
        &mut self,
        index: String,
        msg: &KeyGenPhaseThreeMsg,
    ) -> Result<(), anyhow::Error> {
        let commitment = self
            .msgs
            .phase_one_two_msgs
            .get(&index)
            .ok_or(format_err!(
                "Index is none in phase_one_two_msgs in keygen phase three"
            ))?
            .commitment
            .clone();
        let open = msg.open.clone();

        let dlog_com = DlogCommitment { commitment, open };
        dlog_com.verify()?;
        self.public_signing_key = &self.public_signing_key + dlog_com.get_public_share();

        Ok(())
    }

    fn phase_four_generate_vss(
        msgs: &mut KeyGenMsgs,
        party_index: String,
        threshold: usize,
        share_count: usize,
        private_signing_key: &FE,
        party_ids: Option<Vec<String>>,
    ) -> Result<FE, anyhow::Error> {
        let (vss_scheme, secret_shares) = share_at_indices(
            threshold,
            share_count,
            private_signing_key,
            &party_ids.clone().unwrap(),
        );
        let mut share_private_key = FE::random();
        for i in party_ids.unwrap() {
            let msg = KeyGenPhaseFourMsg {
                vss_scheme: vss_scheme.clone(),
                secret_share: secret_shares.get(&i).unwrap().clone(),
            };

            if i == party_index {
                share_private_key = msg.secret_share.clone();
            }
            let phase_four_msg = MultiKeyGenMessage::PhaseFourMsg(msg);
            let msg_bytes = bincode::serialize(&phase_four_msg)
                .map_err(|why| format_err!("Serialize error in keygen new, cause {}", why))?;
            msgs.phase_four_vss_sending_msgs.insert(i, msg_bytes);
        }

        Ok(share_private_key)
    }

    fn get_phase_four_msg(&self) -> HashMap<String, Vec<u8>> {
        self.msgs.phase_four_vss_sending_msgs.clone()
    }

    fn handle_phase_four_msg(
        &mut self,
        index: String,
        msg: &KeyGenPhaseFourMsg,
    ) -> Result<(), anyhow::Error> {
        // Check VSS
        let q = &self
            .msgs
            .phase_three_msgs
            .get(&index)
            .ok_or(format_err!(
                "Index is none in phase_one_two_msgs in keygen phase four"
            ))?
            .open
            .public_share;

        if !(msg
            .vss_scheme
            .validate_share(&msg.secret_share, self.party_index.clone())
            .is_ok()
            && msg.vss_scheme.commitments[0] == *q)
        {
            return Err(anyhow!("Verify vss failed in keygen phase three"));
        }

        // Compute share_private_key(x_i)
        self.share_private_key = self.share_private_key.clone() + msg.secret_share.clone();

        Ok(())
    }

    fn generate_phase_five_msg(&mut self) -> KeyGenPhaseFiveMsg {
        // TBD:generalize curv
        let dl_proof = DLogProof::<CU, sha2::Sha256>::prove(&self.share_private_key);
        self.share_public_key
            .insert(self.party_index.clone(), dl_proof.pk.clone());
        KeyGenPhaseFiveMsg { dl_proof }
    }

    fn handle_phase_five_msg(
        &mut self,
        index: String,
        msg: &KeyGenPhaseFiveMsg,
    ) -> Result<(), anyhow::Error> {
        DLogProof::verify(&msg.dl_proof).map_err(|why| {
            format_err!(
                "Verify dlog failed error in keygen phase five, cause {}",
                why
            )
        })?;
        self.share_public_key
            .insert(index.clone(), msg.dl_proof.pk.clone());
        Ok(())
    }

    fn generate_result_json_string(&self) -> Result<String, anyhow::Error> {
        let mut share_pks = HashMap::new();
        let ashare_pks = self.share_public_key.clone();
        for a in ashare_pks {
            let pk = vec![
                a.1.x_coord().unwrap().to_hex(),
                a.1.y_coord().unwrap().to_hex(),
            ];
            share_pks.insert(a.0, pk);
        }
        let pubkey = PublicKeyX {
            pk: vec![
                self.public_signing_key.x_coord().unwrap().to_hex(),
                self.public_signing_key.y_coord().unwrap().to_hex(),
            ],
            share_pks: share_pks,
        };
        let privkey = PrivateKeyX {
            cl_sk: self.cl_keypair.cl_priv_key.clone(),
            ec_sk: self.ec_keypair.secret_share.to_bigint().to_hex(),
            share_sk: self.share_private_key.to_bigint().to_hex(),
        };
        let ret = DMZKeyX {
            index: self.party_index.clone(),
            participants: self.party_ids.clone(),
            pubkey,
            privkey,
        };
        let ret_string = serde_json::to_string(&ret)
            .map_err(|why| format_err!("To string failed in keygen phase five, cause {}", why))?;
        Ok(ret_string)
    }

    /// Generate round1 message, output data and send mode (send, send_subset or broadcast)
    pub fn process_begin(&mut self) -> Result<SendingMessages, anyhow::Error> {
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();
        let msg = KeyGenPhaseOneTwoMsg {
            h_caret: self.h_caret.clone(),
            h: (*self.cl_keypair.get_public_key()).clone(),
            ec_pk: self.ec_keypair.get_public_key().clone(),
            gp: GROUP_UPDATE_1827.gq.clone(),
            commitment: self.dlog_com.commitment.clone(),
        };
        let sending_msg = MultiKeyGenMessage::PhaseOneTwoMsg(msg);
        let sending_msg_bytes = bincode::serialize(&sending_msg)
            .map_err(|why| format_err!("Serialize error in keygen process_begin, cause {}", why))?;
        return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
    }

    /// Handle message received and generate next round message, output data and send mode (send, send_subset or broadcast)
    pub fn msg_handler(
        &mut self,
        index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();
        log::debug!(
            "Multi Party msg_handler, from {}, msg: {:?}",
            index,
            recv_msg
        );
        let msg = bincode::deserialize(&recv_msg)
            .map_err(|why| {
                format_err!(
                    "Deserialize error in keygen msg_handler recv_msg, cause {}",
                    why
                )
            })
            .unwrap();
        match msg {
            MultiKeyGenMessage::PhaseOneTwoMsg(msg) => {
                self.msgs
                    .phase_one_two_msgs
                    .insert(index.clone(), msg.clone());
                if self.msgs.phase_one_two_msgs.len() == self.params.share_count {
                    for (_index, msg_) in self.msgs.phase_one_two_msgs.iter() {
                        self.verify_phase_one_msg(&msg_.h_caret, &msg_.h, &msg_.gp)?;
                    }
                    let keygen_phase_three_msg = KeyGenPhaseThreeMsg {
                        open: self.dlog_com.open.clone(),
                    };
                    let sending_msg =
                        MultiKeyGenMessage::PhaseThreeMsg(keygen_phase_three_msg.clone());
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!("Serialize error in keygen phase one two, cause {}", why)
                    })?;
                    return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
                }
            }
            MultiKeyGenMessage::PhaseThreeMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_three_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                // Handle the msg
                self.msgs
                    .phase_three_msgs
                    .insert(index.clone(), msg.clone());

                // Generate the next msg
                if self.msgs.phase_three_msgs.len() == self.params.share_count {
                    for (index, msg) in self.msgs.phase_three_msgs.clone().iter() {
                        if *index != self.party_index {
                            self.handle_phase_three_msg(index.clone(), &msg)?;
                        }
                    }
                    let sending_msg = self.get_phase_four_msg();
                    return Ok(SendingMessages::P2pMessage(sending_msg));
                }
            }
            MultiKeyGenMessage::PhaseFourMsg(msg) => {
                if self.msgs.phase_four_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                self.msgs.phase_four_msgs.insert(index.clone(), msg.clone());

                if self.msgs.phase_four_msgs.len() == self.params.share_count {
                    for (index, msg) in self.msgs.phase_four_msgs.clone().iter() {
                        if *index != self.party_index {
                            self.handle_phase_four_msg(index.clone(), &msg)?;
                        }
                    }
                    let msg_five = self.generate_phase_five_msg();
                    let sending_msg = MultiKeyGenMessage::PhaseFiveMsg(msg_five);
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!("Serialize error in keygen phase four, cause {}", why)
                    })?;
                    return Ok(SendingMessages::BroadcastMessage(sending_msg_bytes));
                }
            }
            MultiKeyGenMessage::PhaseFiveMsg(msg) => {
                if self.msgs.phase_five_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                self.msgs.phase_five_msgs.insert(index.clone(), msg.clone());
                if self.msgs.phase_five_msgs.len() == self.params.share_count {
                    for (index, msg) in self.msgs.phase_five_msgs.clone().iter() {
                        self.handle_phase_five_msg(index.clone(), &msg)?;
                    }
                    let keygen_json = self.generate_result_json_string()?;
                    return Ok(SendingMessages::KeyGenSuccessWithResult(keygen_json));
                }
            }
        }
        Ok(SendingMessages::EmptyMsg)
    }
}
