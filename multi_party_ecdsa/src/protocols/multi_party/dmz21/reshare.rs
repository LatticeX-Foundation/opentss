use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::dmz21::common::*;
use crate::protocols::multi_party::dmz21::message::*;
use crate::utilities::class_group::GROUP_1827;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::vss::*;
use anyhow::{anyhow, format_err};
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::BigInt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct ReshareKeyPhase {
    pub party_index: String,
    pub party_ids: Vec<String>,
    pub new_party_ids: Vec<String>,
    pub new_threshold: usize,
    pub existing_participants_in_new: Vec<String>, // Intersection of party_ids and new_party_ids
    pub keys: Option<DMZKeyX>,
    pub is_new_participant: bool,
    pub msgs: ReshareMsgs,
    pub msgsf: ReshareMsgsFlag,
    pub share_public_key: HashMap<String, GE>,
    pub new_share_private_key: FE,
    pub mutex: Arc<Mutex<usize>>,
    pub public_signing_key: GE,
    pub received_public_keys: HashMap<String, GE>,

}

#[derive(Clone, Debug)]
pub struct ReshareMsgs {
    pub reshare_start_msgs: HashMap<String, ReshareStartMessage>,
    pub reshare_phase_msgs: HashMap<String, HashMap<String, ResharePhaseMsg>>, // sender -> (receiver -> msg)
    pub reshare_dleq_msgs: HashMap<String, ReshareDLEQMsg>,
}

#[derive(Clone, Debug)]
pub struct ReshareMsgsFlag {
    pub reshare_start_msgs: u8,
    pub reshare_phase_msgs: u8,
    pub reshare_dleq_msgs: u8,
}

impl ReshareMsgs {
    pub fn new() -> Self {
        ReshareMsgs {
            reshare_start_msgs: HashMap::new(),
            reshare_phase_msgs: HashMap::new(),
            reshare_dleq_msgs: HashMap::new(),
        }
    }
}

impl ReshareMsgsFlag {
    pub fn new() -> Self {
        ReshareMsgsFlag {
            reshare_start_msgs: 0,
            reshare_phase_msgs: 0,
            reshare_dleq_msgs: 0,
        }
    }
}

impl ReshareKeyPhase {
    pub fn new(
        party_index: String,
        party_ids: Vec<String>,
        new_party_ids: Vec<String>,
        new_threshold: usize,
        keys: Option<String>,
    ) -> Result<Self, anyhow::Error> {
        let mutex = Arc::new(Mutex::new(0));
        let is_new_participant = !party_ids.contains(&party_index);
        let keys: Option<DMZKeyX> = keys.map(|k| serde_json::from_str(&k).expect("Failed to deserialize keys"));

        
        if !is_new_participant && keys.is_none() {
            return Err(anyhow!("Existing participant must provide keys"));
        }
        if is_new_participant && keys.is_some() {
            return Err(anyhow!("New participant must not provide keys"));
        }
        if !is_new_participant && !party_ids.contains(&party_index) {
            return Err(anyhow!("Existing participant index not in party_ids"));
        }

        let public_signing_key = if keys.is_some() {
            GE::from_coords(
                &(BigInt::from_hex(&keys.as_ref().unwrap().pubkey.pk[0]).unwrap()),
                &(BigInt::from_hex(&keys.as_ref().unwrap().pubkey.pk[1]).unwrap())
            ).unwrap()
        } else {
            GE::zero()
        };

        // Compute existing participants still in the new set
        let existing_participants_in_new = party_ids
            .iter()
            .filter(|id| new_party_ids.contains(id))
            .cloned()
            .collect();


        Ok(ReshareKeyPhase {
            party_index,
            party_ids,
            new_party_ids,
            new_threshold,
            existing_participants_in_new,
            keys,
            is_new_participant,
            msgs: ReshareMsgs::new(),
            msgsf: ReshareMsgsFlag::new(),
            share_public_key: HashMap::new(),
            new_share_private_key: FE::zero(),
            mutex,
            public_signing_key,
            received_public_keys: HashMap::new(),
        })
    }

    pub fn process_begin(&mut self) -> Result<SendingMessages, anyhow::Error> {
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();

        let start_msg = ReshareStartMessage {
            new_party_ids: self.new_party_ids.clone(),
            new_threshold: Some(self.new_threshold),
        };
        self.msgs
            .reshare_start_msgs
            .insert(self.party_index.clone(), start_msg.clone());

        let sending_msg = MultiReshareMessage::ReshareStartMessage(start_msg);
        let sending_msg_bytes = bincode::serialize(&sending_msg)?;
        Ok(SendingMessages::BroadcastMessage(sending_msg_bytes))
    }

    pub fn msg_handler(
        &mut self,
        from_index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {
        if !self.party_ids.contains(&from_index) && !self.new_party_ids.contains(&from_index) {
            return Ok(SendingMessages::EmptyMsg);
        }
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();

        let deserialized_msg: MultiReshareMessage = bincode::deserialize(recv_msg)
            .map_err(|why| format_err!("deserialize error: {}", why))?;

        match deserialized_msg {
            MultiReshareMessage::ReshareStartMessage(start_msg) => {
                if self.msgsf.reshare_start_msgs == 1 {
                    return Ok(SendingMessages::EmptyMsg);
                }
    
                self.msgs.reshare_start_msgs.insert(from_index.clone(), start_msg.clone());
    
                if !self.new_party_ids.contains(&self.party_index) {
                    self.msgsf.reshare_start_msgs = 1;
                    return Ok(SendingMessages::EmptyMsg);
                }
    
    
                if self.existing_participants_in_new.contains(&self.party_index) {
                    if self.msgsf.reshare_phase_msgs == 0 {
                        let old_share = FE::from_bigint(
                            &BigInt::from_hex(&self.keys.as_ref().unwrap().privkey.share_sk).unwrap(),
                        );
                        // Compute Lagrange coefficient
                        let s_bigint: Vec<BigInt> = self.existing_participants_in_new.iter()
                            .map(|id| BigInt::from_str_radix(id, 16).unwrap())
                            .collect();
                        let index_bigint = BigInt::from_str_radix(&self.party_index, 16).unwrap();
                        let l_i = map_share_to_new_params(index_bigint, &s_bigint);
                        let a_i = old_share * l_i;
                        // NOTE: Shamir sharing with threshold t should use a polynomial of degree t-1.
                        // The original implementation mistakenly used `t` as the polynomial degree by
                        // passing `t` directly to `share_at_indices` (which interprets the first arg as degree).
                        // This causes inconsistencies specifically when `t == n` (e.g. 3-of-3 after reshare),
                        // breaking later signing invariants that rely on the reconstructed secret being exact.
                        // We correct this by using `self.new_threshold - 1` while preserving externally
                        // observable threshold semantics.
                        let shamir_degree = if self.new_threshold == 0 { 0 } else { self.new_threshold - 1 }; // defensive
                        let (vss_scheme, secret_shares) = share_at_indices(
                            shamir_degree,
                            self.new_party_ids.len(),
                            &a_i,
                            &self.new_party_ids,
                        );
                
                        let mut sending_msgs = HashMap::new();
                        for to_index in &self.new_party_ids {
                            let phase_msg = ResharePhaseMsg {
                                vss_scheme: vss_scheme.clone(),
                                secret_share: secret_shares.get(to_index).unwrap().clone(),
                                public_signing_key: (
                                    self.public_signing_key.x_coord().unwrap().to_hex(),
                                    self.public_signing_key.y_coord().unwrap().to_hex(),
                                ),
                            };
                            let phase_msg_ser = bincode::serialize(&MultiReshareMessage::ResharePhaseMsg(phase_msg))?;
                            sending_msgs.insert(to_index.clone(), phase_msg_ser);
                        }
                
                        // Store self-sent messages
                        let mut self_msgs = HashMap::new();
                        for to_index in &self.new_party_ids {
                            let phase_msg = ResharePhaseMsg {
                                vss_scheme: vss_scheme.clone(),
                                secret_share: secret_shares.get(to_index).unwrap().clone(),
                                public_signing_key: (
                                    self.public_signing_key.x_coord().unwrap().to_hex(),
                                    self.public_signing_key.y_coord().unwrap().to_hex(),
                                ),
                            };
                            self_msgs.insert(to_index.clone(), phase_msg);
                        }
                        self.msgs.reshare_phase_msgs.insert(self.party_index.clone(), self_msgs);
                        self.msgsf.reshare_start_msgs = 1;
                        return Ok(SendingMessages::P2pMessage(sending_msgs));
                    }
                } else {
                    self.msgsf.reshare_start_msgs = 1;
                    return Ok(SendingMessages::EmptyMsg);
                }
            }
    

            MultiReshareMessage::ResharePhaseMsg(phase_msg) => {
                if self.msgsf.reshare_phase_msgs == 1 {
                    return Ok(SendingMessages::EmptyMsg);
                }
            
                if !self.new_party_ids.contains(&self.party_index) {
                    return Ok(SendingMessages::EmptyMsg);
                }
            
                if !self.existing_participants_in_new.contains(&from_index) {
                    return Ok(SendingMessages::EmptyMsg);
                }
            
                // Store the received public key
                let received_pk = GE::from_coords(
                    &BigInt::from_hex(&phase_msg.public_signing_key.0).unwrap(),
                    &BigInt::from_hex(&phase_msg.public_signing_key.1).unwrap(),
                ).unwrap();
                self.received_public_keys.insert(from_index.clone(), received_pk);
            
                if !self.msgs.reshare_phase_msgs.contains_key(&from_index) {
                    self.msgs.reshare_phase_msgs.insert(from_index.clone(), HashMap::new());
                }
                let ms = self.msgs.reshare_phase_msgs.get_mut(&from_index).unwrap();
                if !ms.contains_key(&self.party_index) {
                    ms.insert(self.party_index.clone(), phase_msg.clone());
                }
            
                let mut all_received = true;
                for from_party in &self.existing_participants_in_new {
                    if !self.msgs.reshare_phase_msgs.contains_key(from_party)
                        || !self.msgs.reshare_phase_msgs.get(from_party).unwrap().contains_key(&self.party_index)
                    {
                        all_received = false;
                        break;
                    }
                }
            
                if all_received {
                    // Verify public key consistency

                    let mut public_keys = Vec::new();
                    for (_,point) in self.received_public_keys.clone() {
                        if !public_keys.contains(&point.clone()) {
                            public_keys.push(point);
                        }
                    }
                    // let public_keys: HashSet<GE> = self.received_public_keys.values().cloned().map(|el| el.clone()).collect();
                    if public_keys.len() > 1 {
                        return Err(anyhow!("Inconsistent public keys received from existing participants"));
                    }
                    let consistent_pk = public_keys.into_iter().next().unwrap();
                    if !self.is_new_participant && consistent_pk != self.public_signing_key {
                        return Err(anyhow!("Received public key does not match existing public_signing_key"));
                    }
                    if self.is_new_participant {
                        self.public_signing_key = consistent_pk;
                    }
            
                    // Calculate new share
                    let mut sum_shares = FE::zero();
                    for from_index in &self.existing_participants_in_new {
                        let ms = self.msgs.reshare_phase_msgs.get(from_index).unwrap();
                        let msg = ms.get(&self.party_index).ok_or(format_err!("missing share"))?;
                        if msg.vss_scheme.validate_share(&msg.secret_share, self.party_index.clone()).is_err() {
                            return Err(anyhow!("Invalid VSS share received from {}", from_index));
                        }
                        sum_shares = sum_shares + msg.secret_share.clone();
                    }
                    self.new_share_private_key = sum_shares;
            
                    let dleq_proof = DLogProof::<CU, sha2::Sha256>::prove(&self.new_share_private_key);
                    self.share_public_key.insert(self.party_index.clone(), dleq_proof.pk.clone());
            
                    let dleq_msg = ReshareDLEQMsg {
                        dl_proof: dleq_proof,
                    };
                    let dleq_msg_ser = bincode::serialize(&MultiReshareMessage::ReshareDLEQMsg(dleq_msg))?;
                    self.msgsf.reshare_phase_msgs = 1;
                    return Ok(SendingMessages::BroadcastMessage(dleq_msg_ser));
                }
            }
                        

            MultiReshareMessage::ReshareDLEQMsg(dleq_msg) => {
                if self.msgsf.reshare_dleq_msgs == 1 {
                    return Ok(SendingMessages::EmptyMsg);
                }
                if !self.new_party_ids.contains(&self.party_index) {
                    return Ok(SendingMessages::EmptyMsg);
                }

                self.msgs
                    .reshare_dleq_msgs
                    .insert(from_index.clone(), dleq_msg.clone());

                if self.msgs.reshare_dleq_msgs.len() == self.new_party_ids.len() {
                    for (index, msg) in self.msgs.reshare_dleq_msgs.clone().iter() {
                        if *index != self.party_index {
                            DLogProof::verify(&msg.dl_proof).map_err(|why| {
                                format_err!(
                                    "Verify dlog failed error in reshare phase, cause {}",
                                    why
                                )
                            })?;
                            self.share_public_key
                                .insert(index.clone(), msg.dl_proof.pk.clone());
                        }
                    }
                    let reshare_key_json = self.generate_result_json_string()?;
                    self.msgsf.reshare_dleq_msgs = 1;
                    return Ok(SendingMessages::ReshareKeySuccessWithResult(
                        reshare_key_json,
                    ));
                }
            }
        }
        Ok(SendingMessages::EmptyMsg)
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
    
        let (cl_sk, ec_sk) = if !self.is_new_participant {
            (
                self.keys.as_ref().unwrap().privkey.cl_sk.clone(),
                self.keys.as_ref().unwrap().privkey.ec_sk.clone(),
            )
        } else {
            let mut cl_keypair = ClKeyPair::new(&GROUP_1827);
            let ec_keypair = EcKeyPair::new();
            cl_keypair.update_pk_exp_p();
            (cl_keypair.cl_priv_key, ec_keypair.secret_share.to_bigint().to_hex())
        };
    
        let privkey = PrivateKeyX {
            cl_sk,
            ec_sk,
            share_sk: self.new_share_private_key.to_bigint().to_hex(),
        };
        let ret = DMZKeyX {
            index: self.party_index.clone(),
            participants: self.new_party_ids.clone(),
            pubkey,
            privkey,
        };
        let ret_string = serde_json::to_string(&ret)?;
        Ok(ret_string)
    }
    
}
