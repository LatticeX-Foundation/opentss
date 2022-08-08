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
//! Implement sign algorithm of multi-party ECDSA in dmz
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::dmz21::common::*;
use crate::protocols::multi_party::dmz21::keygen::Parameters;
use crate::protocols::multi_party::dmz21::message::*;
use crate::utilities::class_group::*;
use crate::utilities::clkeypair::ClKeyPair;
use crate::utilities::dl_com_zk::*;
use crate::utilities::eckeypair::EcKeyPair;
use crate::utilities::promise_sigma_multi::*;
use crate::utilities::signature::{Signature, SignatureX};
use crate::utilities::vss::map_share_to_new_params;
use crate::utilities::SECURITY_BITS;
use anyhow::{anyhow, format_err};
use classgroup::ClassGroup;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// Messages of each round in sign
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignMsgs {
    pub phase_one_msgs: HashMap<String, SignPhaseOneMsg>,
    pub phase_two_msgs: HashMap<String, SignPhaseTwoMsg>,
    pub phase_two_sending_msgs: HashMap<String, Vec<u8>>,
    pub phase_three_msgs: HashMap<String, SignPhaseThreeMsg>,
    pub phase_four_msgs: HashMap<String, SignPhaseFourMsg>,
    pub phase_five_step_one_msgs: HashMap<String, SignPhaseFiveStepOneMsg>,
    pub phase_five_step_two_msgs: HashMap<String, SignPhaseFiveStepTwoMsg>,
    pub phase_five_step_four_msgs: HashMap<String, SignPhaseFiveStepFourMsg>,
    pub phase_five_step_five_msgs: HashMap<String, SignPhaseFiveStepFiveMsg>,
    pub phase_five_step_seven_msgs: HashMap<String, SignPhaseFiveStepSevenMsg>,
}

/// Sign struct
#[derive(Debug, Clone)]
pub struct SignPhase {
    pub party_index: String,
    pub party_num: usize,
    pub params: Parameters,
    pub subset: Vec<String>,
    pub ec_keypair: EcKeyPair,
    pub cl_keypair: ClKeyPair,
    pub public_signing_key: GE,
    pub omega: FE,
    pub big_omega_map: HashMap<String, GE>,
    pub k: FE,
    pub gamma: FE,
    pub delta: FE,
    pub sigma: FE,
    pub delta_sum: FE,
    pub beta_map: HashMap<String, FE>,
    pub v_map: HashMap<String, FE>,
    pub precomputation: HashMap<String, (Ciphertext, Ciphertext, GE)>,
    pub msgs: SignMsgs,
    pub dl_com: DlogCommitment,
    pub mutex: Arc<Mutex<usize>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OfflineResult {
    pub party_index: String,
    pub party_num: usize,
    pub subset: Vec<String>,
    pub k: FE,
    pub sigma: FE,
    pub delta: FE,
    pub delta_sum: FE,
    pub msgs: SignMsgs,
    pub public_signing_key: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OfflineResultX {
    pub data: String,
}

#[derive(Debug)]
pub struct SignPhaseOnline {
    pub party_index: String,
    pub party_num: usize,
    pub subset: Vec<String>,
    pub message: FE,
    pub k: FE,
    pub sigma: FE,
    pub r_x: FE,
    pub r_point: GE,
    pub rho: FE,
    pub l: FE,
    pub delta: FE,
    pub delta_sum: FE,
    pub msgs: SignMsgs,
    pub public_signing_key: GE,
    pub msg_step_one: SignPhaseFiveStepOneMsg,
    pub msg_step_two: SignPhaseFiveStepTwoMsg,
    pub msg_step_seven: SignPhaseFiveStepSevenMsg,
    pub msg_step_five: SignPhaseFiveStepFiveMsg,
    pub mutex: Arc<Mutex<usize>>,
}

impl SignMsgs {
    pub fn new() -> Self {
        Self {
            phase_one_msgs: HashMap::new(),
            phase_two_msgs: HashMap::new(),
            phase_two_sending_msgs: HashMap::new(),
            phase_three_msgs: HashMap::new(),
            phase_four_msgs: HashMap::new(),
            phase_five_step_one_msgs: HashMap::new(),
            phase_five_step_two_msgs: HashMap::new(),
            phase_five_step_four_msgs: HashMap::new(),
            phase_five_step_five_msgs: HashMap::new(),
            phase_five_step_seven_msgs: HashMap::new(),
        }
    }

    pub fn clean(&mut self) {
        self.phase_one_msgs.clear();
        self.phase_two_msgs.clear();
        self.phase_three_msgs.clear();
        self.phase_four_msgs.clear();
        self.phase_five_step_one_msgs.clear();
        self.phase_five_step_two_msgs.clear();
        self.phase_five_step_four_msgs.clear();
        self.phase_five_step_five_msgs.clear();
        self.phase_five_step_seven_msgs.clear();
    }
}

impl SignPhase {
    /// partyid: The party id(index). Hex-string. (0, the modulus of the curve)
    /// params: t,n. t>0, n>t.
    /// subset: The set of parties that involved in signing.
    /// keys: The output of KeyGen, including pk,sk.
    pub fn new(
        partyid: String,
        params: Parameters,
        subset: &Vec<String>,
        keys: &String,
    ) -> Result<Self, anyhow::Error> {
        let mutex = Arc::new(Mutex::new(0));
        let ret: DMZKeyX = serde_json::from_str(keys)
            .map_err(|why| format_err!("From string failed in sign new, cause {}", why))?;
        let mut share_pks = HashMap::new();
        let ashare_pks = ret.pubkey.share_pks.clone();
        for a in ashare_pks {
            let x = BigInt::from_hex(a.1.get(0).unwrap()).unwrap();
            let y = BigInt::from_hex(a.1.get(1).unwrap()).unwrap();
            share_pks.insert(a.0, GE::from_coords(&x, &y).unwrap());
        }
        let pubkey = PublicKey {
            pk: {
                let x = BigInt::from_hex(ret.pubkey.pk.get(0).unwrap()).unwrap();
                let y = BigInt::from_hex(ret.pubkey.pk.get(1).unwrap()).unwrap();
                GE::from_coords(&x, &y).unwrap()
            },
            share_pks: share_pks,
        };
        let privkey = PrivateKey {
            cl_sk: ret.privkey.cl_sk,
            ec_sk: FE::from_bigint(&BigInt::from_hex(&ret.privkey.ec_sk).unwrap()),
            share_sk: FE::from_bigint(&BigInt::from_hex(&ret.privkey.share_sk).unwrap()),
        };
        let keygen_result = DMZKey {
            index: ret.index,
            participants: ret.participants,
            pubkey,
            privkey,
        };

        {
            // valid check
            assert_eq!(keygen_result.index, partyid);
            for s in subset.iter() {
                if !keygen_result.participants.contains(s) {
                    return Err(anyhow!(
                        "subset id:{} not in the participants:{:?}",
                        *s,
                        keygen_result.participants
                    ));
                }
            }
        }

        let ec_keypair = EcKeyPair::from_sk(keygen_result.privkey.ec_sk);
        let cl_keypair = ClKeyPair::from_sk(keygen_result.privkey.cl_sk, &GROUP_UPDATE_1827);
        let share_public_key_map = keygen_result.pubkey.share_pks;

        let party_num = subset.len();
        if party_num < params.threshold {
            return Err(anyhow!("Party number less than threshold"));
        }

        // Compute lambda
        let share_ids_sub = subset
            .iter()
            .map(|i| BigInt::from_str_radix(&i, 16).unwrap())
            .collect::<Vec<BigInt>>();
        let lamda = map_share_to_new_params(
            BigInt::from_str_radix(&partyid, 16).unwrap(),
            &share_ids_sub,
        );
        let omega = lamda * keygen_result.privkey.share_sk;
        let mut big_omega_map = HashMap::new();
        for i in subset.iter().zip(share_ids_sub.clone().iter()) {
            let share_public_key = share_public_key_map.get(i.0).ok_or(format_err!(
                "Index is none in phase_one_two_msgs in sign new"
            ))?;
            let big_omega = share_public_key
                * &(map_share_to_new_params((*i.1).clone(), &share_ids_sub.clone()));
            big_omega_map.insert((*i.0).clone(), big_omega);
        }
        // Generate promise sigma
        let k = FE::random();

        // Generate commitment
        let gamma_pair = EcKeyPair::new();
        let gamma = gamma_pair.get_secret_key().clone();
        let dl_com = DlogCommitment::new(&gamma_pair.get_public_key());

        let delta = &k * &gamma;
        let sigma = &k * &omega;
        let mut ret = SignPhase {
            party_index: partyid,
            party_num,
            params,
            subset: subset.to_vec(),
            ec_keypair,
            cl_keypair,
            public_signing_key: keygen_result.pubkey.pk,
            omega,
            big_omega_map,
            k,
            gamma,
            delta,
            sigma,
            delta_sum: FE::random(), // Init delta_sum, compute later.
            beta_map: HashMap::new(),
            v_map: HashMap::new(),
            precomputation: HashMap::new(),
            msgs: SignMsgs::new(),
            dl_com,
            mutex,
        };
        ret.pre_computation();
        Ok(ret)
    }

    fn pre_computation(&mut self) {
        let base = GE::generator();
        let zero = FE::zero();
        for index in self.subset.iter() {
            let beta = FE::random();
            let (r_cipher_1, _r_blind) =
                CLGroup::encrypt_without_r(&GROUP_UPDATE_1827, &(zero.clone() - beta.clone()));
            self.beta_map.insert((*index).clone(), beta);

            let v = FE::random();
            let (r_cipher_2, _r_blind) =
                CLGroup::encrypt_without_r(&GROUP_UPDATE_1827, &(zero.clone() - v.clone()));
            let b = base * &v;
            self.v_map.insert((*index).clone(), v);

            self.precomputation
                .insert((*index).clone(), (r_cipher_1, r_cipher_2, b));
        }
    }

    fn handle_phase_one_msg(
        &mut self,
        index: String,
        msg: &SignPhaseOneMsg,
    ) -> Result<SignPhaseTwoMsg, anyhow::Error> {
        // TBD: check ec cl pk
        // Verify promise proof
        msg.proof.verify(&GROUP_UPDATE_1827, &msg.promise_state)?;

        // Homo
        let cipher = &msg.promise_state.cipher;

        let (pre_cipher_1, pre_cipher_2, b) = self.precomputation.get(&index).ok_or(
            format_err!("Index is none in pre_cipher in sign offline phase one"),
        )?;

        // todo, optimized
        let mut homocipher = pre_cipher_1.clone();
        let mut homocipher_plus = pre_cipher_1.clone();
        let mut t_p = FE::zero();
        let mut t_p_plus = FE::zero();

        let upper = mpz_to_bigint(&GROUP_UPDATE_1827.stilde)
            * BigInt::from(2 as u32).pow(40)
            * FE::group_order();
        crossbeam::scope(|thread| {
            thread.spawn(|_| {
                {
                    // Generate random.
                    let t = BigInt::sample_below(&upper);
                    t_p = FE::from_bigint(&t.mod_floor(&FE::group_order()));
                    let rho_plus_t = into_mpz(&self.gamma) + bigint_to_mpz(&t);

                    // Handle CL cipher.
                    let mut c11 = cipher.cl_cipher.c1.clone();
                    c11.pow(rho_plus_t.clone());
                    let mut c21 = cipher.cl_cipher.c2.clone();
                    c21.pow(rho_plus_t);
                    let c1 = c11 * pre_cipher_1.c1.clone();
                    let c2 = c21 * pre_cipher_1.c2.clone();
                    homocipher = Ciphertext { c1, c2 };
                }
            });

            thread.spawn(|_| {
                {
                    // Generate random.
                    let t = BigInt::sample_below(&upper);
                    t_p_plus = FE::from_bigint(&t.mod_floor(&FE::group_order()));
                    let omega_plus_t = into_mpz(&self.omega) + bigint_to_mpz(&t);

                    // Handle CL cipher.
                    let mut c11 = cipher.cl_cipher.c1.clone();
                    c11.pow(omega_plus_t.clone());
                    let mut c21 = cipher.cl_cipher.c2.clone();
                    c21.pow(omega_plus_t);
                    let c1 = c11 * pre_cipher_2.c1.clone();
                    let c2 = c21 * pre_cipher_2.c2.clone();
                    homocipher_plus = Ciphertext { c1, c2 };
                }
            });
        })
        .unwrap();

        let msg_two = SignPhaseTwoMsg {
            homocipher,
            homocipher_plus,
            t_p,
            t_p_plus,
            b: b.clone(),
        };
        Ok(msg_two)
    }

    fn handle_phase_two_msg(
        &mut self,
        index: String,
        msg: &SignPhaseTwoMsg,
    ) -> Result<(), anyhow::Error> {
        // Compute delta
        let k_mul_t = self.k.clone() * msg.t_p.clone();
        let alpha = CLGroup::decrypt(
            &GROUP_UPDATE_1827,
            self.cl_keypair.get_secret_key(),
            &msg.homocipher,
        ) - k_mul_t;

        let beta = self.beta_map.get(&index).ok_or(format_err!(
            "Index is none in beta in sign offline phase two"
        ))?;
        self.delta = self.delta.clone() + alpha + beta;

        // Compute sigma
        let k_mul_t_plus = self.k.clone() * msg.t_p_plus.clone();
        let miu = CLGroup::decrypt(
            &GROUP_UPDATE_1827,
            self.cl_keypair.get_secret_key(),
            &msg.homocipher_plus,
        ) - k_mul_t_plus;

        let v = self
            .v_map
            .get(&index)
            .ok_or(format_err!("Index is none in v in sign offline phase two"))?;
        self.sigma = self.sigma.clone() + miu.clone() + v;

        // Check kW = uP + B
        let big_omega = self.big_omega_map.get(&index).ok_or(format_err!(
            "Index is none in big_omega in sign offline phase two"
        ))?;
        let k_omega = big_omega * &self.k;
        let base = GE::generator();
        let up_plus_b = base * miu + msg.b.clone();
        if k_omega != up_plus_b {
            return Err(anyhow!("Handle msg failed in sign offline phase two"));
        }
        assert_eq!(k_omega, up_plus_b);

        Ok(())
    }

    fn phase_two_compute_delta_sum_msg(&mut self) -> Result<(), anyhow::Error> {
        if self.msgs.phase_three_msgs.len() != self.party_num {
            return Err(anyhow!(
                "Compute delta sum failed in sign offline phase three"
            ));
        }

        self.delta_sum = self
            .msgs
            .phase_three_msgs
            .iter()
            .fold(FE::zero(), |acc, (_i, v)| acc + v.delta.clone());

        // Can't invert zero
        if self.delta_sum == FE::zero() {
            return Err(anyhow!("Invert zero error in sign offline phase three"));
        }

        Ok(())
    }

    fn handle_phase_four_msg(
        &mut self,
        index: String,
        msg: &SignPhaseFourMsg,
    ) -> Result<(), anyhow::Error> {
        let msg_one = self.msgs.phase_one_msgs.get(&index).ok_or(format_err!(
            "Index is none in msg_one in sign offline phase four"
        ))?;
        DlogCommitment::verify_dlog(&msg_one.commitment, &msg.open)?;

        Ok(())
    }

    /// Generate sign offline round1 message, output data and send mode (send, send_subset or broadcast)
    pub fn process_begin(&mut self) -> Result<SendingMessages, anyhow::Error> {
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();
        if self.subset.contains(&self.party_index) {
            let cipher = PromiseCipher::encrypt(
                &GROUP_UPDATE_1827,
                self.cl_keypair.get_public_key(),
                self.ec_keypair.get_public_key(),
                &self.k,
            );
            let promise_state = PromiseState {
                cipher: cipher.0, // {ec_cipher, cl_cipher} ====> {c'_{k_i}, c_{k_i}}
                ec_pub_key: self.ec_keypair.get_public_key().clone(), // pk'_i
                cl_pub_key: self.cl_keypair.get_public_key().clone(), // pk_i
            };
            let promise_wit = PromiseWit {
                m: self.k.clone(), // k_i
                r1: cipher.1,      // r'_i
                r2: cipher.2,      // r_i
            };
            let proof = PromiseProof::prove(&GROUP_UPDATE_1827, &promise_state, &promise_wit);
            let msg = SignPhaseOneMsg {
                commitment: self.dl_com.commitment.clone(),
                promise_state,
                proof,
            };
            let msg_sending = MultiSignMessage::PhaseOneMsg(msg);
            let msg_sending_bytes = bincode::serialize(&msg_sending)
                .map_err(|why| format!("bincode serialize error: {}", why))
                .unwrap();
            return Ok(SendingMessages::SubsetMessage(msg_sending_bytes));
        }
        Ok(SendingMessages::EmptyMsg)
    }

    /// Handle message received and generate next round message in offline phase, output data and send mode (send, send_subset or broadcast)
    pub fn msg_handler(
        &mut self,
        index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {
        if !self.subset.contains(&index) {
            return Ok(SendingMessages::EmptyMsg);
        }

        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();

        let msg = bincode::deserialize(&recv_msg).map_err(|why| {
            format_err!(
                "Deserialize error in sign offline msg_handler recv_msg, cause {}",
                why
            )
        })?;
        match msg {
            MultiSignMessage::PhaseOneMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_one_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }
                // Handle the msg and generate the reply msg
                self.msgs.phase_one_msgs.insert(index.clone(), msg.clone());
                if self.msgs.phase_one_msgs.len() == self.party_num {
                    let phase_two_sending_msgs: HashMap<String, SignPhaseTwoMsg> = HashMap::new();
                    let mutex_msgs = Arc::new(Mutex::new(phase_two_sending_msgs));
                    for (index, msg) in self.msgs.clone().phase_one_msgs.into_iter() {
                        let mutex_msgs = Arc::clone(&mutex_msgs);
                        if *index == self.party_index {
                            let msg_two = SignPhaseTwoMsg::new();
                            let mut msgs = mutex_msgs.lock().unwrap();
                            (*msgs).insert(index.clone(), msg_two);
                        } else {
                            let mut phase = self.clone();
                            let msg_two = phase.handle_phase_one_msg(index.clone(), &msg).unwrap();
                            let mut msgs = mutex_msgs.lock().unwrap();
                            (*msgs).insert(index.clone(), msg_two);
                        }
                    }
                    let result = &*mutex_msgs.lock().unwrap();
                    for (index, msg) in result.into_iter() {
                        let sending_msg = MultiSignMessage::PhaseTwoMsg((*msg).clone());
                        let sending_msg_bytes = bincode::serialize(&sending_msg)
                            .map_err(|why| {
                                format_err!(
                                    "Serialize error in sign offline phase one, cause {}",
                                    why
                                )
                            })
                            .unwrap();
                        self.msgs
                            .phase_two_sending_msgs
                            .insert(index.clone(), sending_msg_bytes);
                    }
                }
                return Ok(SendingMessages::P2pMessage(
                    self.msgs.phase_two_sending_msgs.clone(),
                ));
            }
            MultiSignMessage::PhaseTwoMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_two_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                // Handle the msg
                self.msgs.phase_two_msgs.insert(index.clone(), msg.clone());

                // Generate the next msg
                if self.msgs.phase_two_msgs.len() == self.party_num {
                    for (index_, msg_) in self.msgs.phase_two_msgs.clone().iter() {
                        if *index_ != self.party_index {
                            self.handle_phase_two_msg(index_.clone(), &msg_)?;
                        }
                    }
                    let msg_three = SignPhaseThreeMsg {
                        delta: self.delta.clone(),
                    };
                    let sending_msg = MultiSignMessage::PhaseThreeMsg(msg_three);
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!("Serialize error in sign offline phase two, cause {}", why)
                    })?;
                    return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                }
            }
            MultiSignMessage::PhaseThreeMsg(msg) => {
                self.msgs.phase_three_msgs.insert(index, msg.clone());
                if self.msgs.phase_three_msgs.len() == self.party_num {
                    self.phase_two_compute_delta_sum_msg()?;
                    let msg_four = SignPhaseFourMsg {
                        open: self.dl_com.clone().open,
                    };
                    let sending_msg = MultiSignMessage::PhaseFourMsg(msg_four.clone());
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!("Serialize error in sign offline phase three, cause {}", why)
                    })?;
                    return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                }
            }
            MultiSignMessage::PhaseFourMsg(msg) => {
                if self.msgs.phase_four_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }
                self.msgs.phase_four_msgs.insert(index, msg.clone());
                if self.msgs.phase_four_msgs.len() == self.party_num {
                    for (index_, msg_) in self.msgs.phase_four_msgs.clone().iter() {
                        if *index_ != self.party_index {
                            self.handle_phase_four_msg(index_.clone(), &msg_)?;
                        }
                    }
                    let offline_result = OfflineResult {
                        party_index: self.party_index.clone(),
                        party_num: self.party_num,
                        subset: self.subset.clone(),
                        k: self.k.clone(),
                        sigma: self.sigma.clone(),
                        delta: self.delta.clone(),
                        delta_sum: self.delta_sum.clone(),
                        msgs: self.msgs.clone(),
                        public_signing_key: self.public_signing_key.clone(),
                    };
                    let retb = bincode::serialize(&offline_result).unwrap();
                    let offline_result_string = hex::encode(retb);
                    let offline_result_string = serde_json::to_string(&{
                        OfflineResultX {
                            data: offline_result_string,
                        }
                    })
                    .map_err(|why| format_err!("To string failed: {}", why))
                    .unwrap();
                    return Ok(SendingMessages::SignOfflineSuccessWithResult(
                        offline_result_string,
                    ));
                }
            }
            _ => {}
        }
        Ok(SendingMessages::EmptyMsg)
    }

    #[deprecated(since = "0.2.0", note = "please use `msg_handler` instead")]
    pub fn msg_handler_offline(
        &mut self,
        index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {
        self.msg_handler(index, recv_msg)
    }
}

impl SignPhaseOnline {
    #[deprecated(since = "0.2.0", note = "please use `new` instead")]
    pub fn new_online(
        offline_result: &String,
        message_bytes: Vec<u8>,
    ) -> Result<Self, anyhow::Error> {
        SignPhaseOnline::new(offline_result, message_bytes)
    }
    #[deprecated(since = "0.2.0", note = "please use `process_begin` instead")]
    pub fn process_online_begin(&mut self) -> Result<SendingMessages, anyhow::Error> {
        self.process_begin()
    }
    #[deprecated(since = "0.2.0", note = "please use `msg_handler` instead")]
    pub fn msg_handler_online(
        &mut self,
        index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {
        self.msg_handler(index, recv_msg)
    }

    /// offline_result: The output of SignOffline.
    /// message_bytes: The hash value of the message to be signed, 32 bytes.
    pub fn new(offline_result: &String, message_bytes: Vec<u8>) -> Result<Self, anyhow::Error> {
        let offline_result: OfflineResultX = serde_json::from_str(&offline_result)
            .map_err(|why| format_err!("from string error: {}", why))
            .unwrap();
        let retb = hex::decode(offline_result.data).unwrap();
        let offline_result: OfflineResult = bincode::deserialize(&retb).unwrap();

        let mutex = Arc::new(Mutex::new(0));

        let message_bigint = BigInt::from_bytes(&message_bytes);
        let message = FE::from_bigint(&message_bigint);

        // compute r_x
        let g = GE::generator().to_point();
        let r = offline_result
            .msgs
            .phase_four_msgs
            .iter()
            .fold(g.clone(), |acc, (_i, v)| acc + v.open.public_share.clone())
            - g;
        let r_point = r * offline_result.delta_sum.invert().unwrap(); // todo:check is_zero
        let r_x = FE::from_bigint(
            &r_point
                .x_coord()
                .ok_or(format_err!(
                    "Index is none in x_coor in process_online_begin"
                ))?
                .mod_floor(&FE::group_order()),
        );

        let s_i = (message.clone()) * offline_result.k.clone()
            + offline_result.sigma.clone() * r_x.clone();
        let l_i = FE::random();
        let rho_i = FE::random();
        let l_i_rho_i = l_i.clone() * rho_i.clone();
        let base = GE::generator();
        let v_i = r_point.clone() * &s_i + base * l_i.clone();
        let a_i = base * rho_i.clone();
        let b_i = base * l_i_rho_i;

        // Generate com
        let blind = BigInt::sample(SECURITY_BITS);
        let input_hash = sha2::Sha256::new()
            .chain_points([&v_i, &a_i, &b_i])
            .result_bigint();

        let commitment =
            HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &blind,
            );

        // Generate zk proof
        let witness = HomoElGamalWitness {
            r: l_i.clone(),
            x: s_i.clone(),
        };
        let delta = HomoElGamalStatement {
            G: a_i.clone(),
            H: r_point.clone(),
            Y: base.to_point(),
            D: v_i.clone(),
            E: b_i.clone(),
        };
        let dl_proof = DLogProof::prove(&rho_i);
        let proof = HomoELGamalProof::prove(&witness, &delta);

        let msg_step_one = SignPhaseFiveStepOneMsg { commitment };
        let msg_step_two = SignPhaseFiveStepTwoMsg {
            v_i,
            a_i,
            b_i,
            blind,
            dl_proof,
            proof,
        };
        let msg_step_seven = SignPhaseFiveStepSevenMsg { s_i };
        let online_sign = SignPhaseOnline {
            party_index: offline_result.party_index,
            party_num: offline_result.party_num,
            subset: offline_result.subset,
            message,
            k: offline_result.k,
            sigma: offline_result.sigma,
            r_x,
            r_point,
            rho: rho_i,
            l: l_i,
            delta: offline_result.delta,
            delta_sum: offline_result.delta_sum,
            msgs: offline_result.msgs,
            public_signing_key: offline_result.public_signing_key,
            msg_step_one,
            msg_step_two,
            msg_step_seven,
            msg_step_five: SignPhaseFiveStepFiveMsg::new(),
            mutex,
        };
        return Ok(online_sign);
    }

    fn handle_phase_five_step_two_msg(
        &mut self,
        index: String,
        msg: &SignPhaseFiveStepTwoMsg,
    ) -> Result<(), anyhow::Error> {
        let msg_one = self
            .msgs
            .phase_five_step_one_msgs
            .get(&index)
            .ok_or(format_err!(
                "Index is none in phase_five_step_one_msgs in sign online phase five step two"
            ))?;
        // Verify commitment
        let input_hash = sha2::Sha256::new()
            .chain_points([&msg.v_i, &msg.a_i, &msg.b_i])
            .result_bigint();

        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &input_hash,
            &msg.blind,
        ) != msg_one.commitment
        {
            return Err(anyhow!(
                "Open ge commitment failed in sign online phase five step two"
            ));
        }

        // Verify zk proof
        let delta = HomoElGamalStatement {
            G: msg.a_i.clone(),
            H: self.r_point.clone(),
            Y: GE::generator().to_point(),
            D: msg.v_i.clone(),
            E: msg.b_i.clone(),
        };

        msg.proof.verify(&delta).map_err(|why| {
            format_err!(
                "Verify homomorphic elgamal failed in sign online phase five steo two, cause {}",
                why
            )
        })?;
        DLogProof::verify(&msg.dl_proof).map_err(|why| {
            format_err!(
                "Verify dlog failed in sign online phase five steo two, cause {}",
                why
            )
        })?;

        Ok(())
    }

    fn generate_phase_five_step_four_msg(
        &mut self,
        message: FE,
    ) -> Result<SignPhaseFiveStepFourMsg, anyhow::Error> {
        let my_msg = self
            .msgs
            .phase_five_step_two_msgs
            .get(&self.party_index)
            .ok_or(format_err!(
                "Index is none in phase_five_step_two_msgs in sign online phase five step two"
            ))?;
        let mut v_sum = my_msg.v_i.clone();
        let mut a_sum = my_msg.a_i.clone();
        for (index, msg) in self.msgs.phase_five_step_two_msgs.iter() {
            // Skip my own check
            if *index == self.party_index {
                continue;
            }

            v_sum = v_sum + msg.v_i.clone();
            a_sum = a_sum + msg.a_i.clone();
        }

        // Compute V = -mP -rQ + sum (vi)
        let base = GE::generator();
        let mp = base * message;
        let rq = self.public_signing_key.clone() * &self.r_x;
        let v_big = v_sum - mp - rq;
        let u_i = v_big * self.rho.clone();
        let t_i = a_sum * self.l.clone();
        let input_hash = sha2::Sha256::new()
            .chain_points([&u_i, &t_i])
            .result_bigint();

        let blind = BigInt::sample(SECURITY_BITS);
        let commitment =
            HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &blind,
            );

        let msg_step_four = SignPhaseFiveStepFourMsg { commitment };
        let msg_step_five = SignPhaseFiveStepFiveMsg { blind, u_i, t_i };
        self.msg_step_five = msg_step_five;

        Ok(msg_step_four)
    }

    fn handle_phase_five_step_five_msg(
        &self,
        index: String,
        msg_five: &SignPhaseFiveStepFiveMsg,
    ) -> Result<(), anyhow::Error> {
        let msg_four = self
            .msgs
            .phase_five_step_four_msgs
            .get(&index)
            .ok_or(format_err!(
                "Index is none in phase_five_step_four_msgs in sign online phase five step five"
            ))?;
        let input_hash = sha2::Sha256::new()
            .chain_points([&msg_five.u_i, &msg_five.t_i])
            .result_bigint();

        if HashCommitment::<sha2::Sha256>::create_commitment_with_user_defined_randomness(
            &input_hash,
            &msg_five.blind,
        ) != msg_four.commitment
        {
            return Err(anyhow!(
                "Open ge commitment failed in sign online phase five step five"
            ));
        }

        Ok(())
    }

    fn phase_five_step_six_check_sum_a_t(&self) -> Result<(), anyhow::Error> {
        let base = GE::generator().to_point();
        let biased_sum_ti = self
            .msgs
            .phase_five_step_five_msgs
            .iter()
            .fold(base.clone(), |acc, (_i, x)| acc + x.t_i.clone());
        let biased_sum_ti_minus_ui = self
            .msgs
            .phase_five_step_five_msgs
            .iter()
            .fold(biased_sum_ti, |acc, (_i, x)| acc - x.u_i.clone());

        if base != biased_sum_ti_minus_ui {
            return Err(anyhow!(
                "Verify sum of a and t failed in sign online phase five step five"
            ));
        }

        Ok(())
    }

    fn calculate_recovery_id(&self, s: &FE) -> Result<u8, anyhow::Error> {
        /*
          calculate recovery id
          v = (R.x > N) ? 2 : 0 | R.y is even ? 0 : else 1
          if (s > N/2) then v^=1 else do nothing
        */
        let mut recid = 0u8;
        let n = FE::group_order();
        let half_n = n >> 1;
        let rx = self.r_point.x_coord().ok_or(format_err!(
            "Index is none in x_coor in process_online_begin"
        ))?;
        let ry = self.r_point.y_coord().ok_or(format_err!(
            "Index is none in y_coor in process_online_begin"
        ))?;

        if rx > *n {
            recid = 2;
        }
        if ry.is_odd() {
            recid |= 1;
        }
        let s_bn = s.to_bigint();
        if s_bn > half_n {
            recid ^= 1;
        }
        Ok(recid)
    }

    fn phase_five_step_eight_generate_signature_msg(&self) -> Result<Signature, anyhow::Error> {
        if self.msgs.phase_five_step_seven_msgs.len() != self.party_num {
            return Err(anyhow!(
                "Left not equal to right in sign online phase five step seven"
            ));
        }

        let mut s = self
            .msgs
            .phase_five_step_seven_msgs
            .iter()
            .fold(FE::zero(), |acc, (_i, x)| acc + x.s_i.clone());
        let recid = self.calculate_recovery_id(&s)?;
        let s_bn = s.to_bigint();
        let s_tag_bn = FE::group_order() - &s_bn;
        if s_bn > s_tag_bn {
            s = FE::from_bigint(&s_tag_bn);
        }

        Ok(Signature {
            s,
            r: self.r_x.clone(),
            recid: recid,
        })
    }

    /// Generate Sign online round1 message, output data and send mode (send, send_subset or broadcast)
    pub fn process_begin(&mut self) -> Result<SendingMessages, anyhow::Error> {
        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();
        if self.subset.contains(&self.party_index) {
            let msg = self.msg_step_one.clone();
            let msg_sending = MultiSignMessage::PhaseFiveStepOneMsg(msg);
            let msg_sending_bytes = bincode::serialize(&msg_sending)
                .map_err(|why| format!("bincode serialize error: {}", why))
                .unwrap();
            return Ok(SendingMessages::SubsetMessage(msg_sending_bytes));
        }
        Ok(SendingMessages::EmptyMsg)
    }

    /// Handle message received and generate next round message in online phase, output data and send mode (send, send_subset or broadcast)
    pub fn msg_handler(
        &mut self,
        index: String,
        recv_msg: &Vec<u8>,
    ) -> Result<SendingMessages, anyhow::Error> {
        if !self.subset.contains(&index) {
            return Ok(SendingMessages::EmptyMsg);
        }

        let lock = Arc::clone(&self.mutex);
        let _lock = lock.lock().unwrap();
        let msg = bincode::deserialize(&recv_msg)
            .map_err(|why| format_err!("bincode deserialize error: {}", why))
            .unwrap();
        match msg {
            MultiSignMessage::PhaseFiveStepOneMsg(msg) => {
                self.msgs
                    .phase_five_step_one_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_one_msgs.len() == self.party_num {
                    let msg_five_two = self.msg_step_two.clone();
                    let sending_msg = MultiSignMessage::PhaseFiveStepTwoMsg(msg_five_two.clone());
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!(
                            "Serialize error in sign online phase five steo one, cause {}",
                            why
                        )
                    })?;
                    return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                }
            }
            MultiSignMessage::PhaseFiveStepTwoMsg(msg) => {
                // Already received the msg
                if self.msgs.phase_five_step_two_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }

                // Handle the msg
                self.msgs
                    .phase_five_step_two_msgs
                    .insert(index.clone(), msg.clone());
                // Generate the next msg
                if self.msgs.phase_five_step_two_msgs.len() == self.party_num {
                    for (index_, msg_) in self.msgs.phase_five_step_two_msgs.clone().iter() {
                        self.handle_phase_five_step_two_msg(index_.clone(), &msg_)?;
                    }
                    let msg_five_four =
                        self.generate_phase_five_step_four_msg(self.message.clone())?;
                    let sending_msg = MultiSignMessage::PhaseFiveStepFourMsg(msg_five_four.clone());

                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!(
                            "Serialize error in sign online phase five step two, cause {}",
                            why
                        )
                    })?;
                    return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                }
            }
            MultiSignMessage::PhaseFiveStepFourMsg(msg) => {
                self.msgs
                    .phase_five_step_four_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_four_msgs.len() == self.party_num {
                    let msg_five_five = self.msg_step_five.clone();
                    let sending_msg = MultiSignMessage::PhaseFiveStepFiveMsg(msg_five_five.clone());
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!(
                            "Serialize error in sign online phase five step four, cause {}",
                            why
                        )
                    })?;
                    return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                }
            }
            MultiSignMessage::PhaseFiveStepFiveMsg(msg) => {
                if self.msgs.phase_five_step_five_msgs.get(&index).is_some() {
                    return Ok(SendingMessages::EmptyMsg);
                }
                self.msgs
                    .phase_five_step_five_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_five_msgs.len() == self.party_num {
                    for (index_, msg_) in self.msgs.phase_five_step_five_msgs.clone().iter() {
                        self.handle_phase_five_step_five_msg(index_.clone(), &msg_)?;
                    }
                    self.phase_five_step_six_check_sum_a_t()
                            .map_err(|why| format_err!("Verify sum of a and t failed in sign online phase five step five, cause {}", why))?;
                    let msg_seven = self.msg_step_seven.clone();
                    let sending_msg = MultiSignMessage::PhaseFiveStepSevenMsg(msg_seven.clone());
                    let sending_msg_bytes = bincode::serialize(&sending_msg).map_err(|why| {
                        format_err!(
                            "Serialize error in sign online phase five step five, cause {}",
                            why
                        )
                    })?;
                    return Ok(SendingMessages::SubsetMessage(sending_msg_bytes));
                }
            }
            MultiSignMessage::PhaseFiveStepSevenMsg(msg) => {
                self.msgs
                    .phase_five_step_seven_msgs
                    .insert(index, msg.clone());
                if self.msgs.phase_five_step_seven_msgs.len() == self.party_num {
                    let signature = self.phase_five_step_eight_generate_signature_msg()?;
                    signature.verify(&self.public_signing_key, &self.message)?;

                    let s = signature.s.to_bigint().to_hex();
                    let r = signature.r.to_bigint().to_hex();
                    let recid = signature.recid;
                    let ret = SignatureX { s, r, recid };
                    let signature_json = serde_json::to_string(&ret).map_err(|why| {
                        format_err!("To string failed in keygen phase five, cause {}", why)
                    })?;

                    return Ok(SendingMessages::SignOnlineSuccessWithResult(signature_json));
                }
            }
            _ => {}
        }

        Ok(SendingMessages::EmptyMsg)
    }
}
