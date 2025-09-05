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
use crate::communication::sending_messages::SendingMessages;
use crate::protocols::multi_party::dmz21::common::DMZKeyX;
use crate::protocols::multi_party::dmz21::common::PublicKeyX;
use crate::protocols::multi_party::dmz21::keygen::KeyGenPhase;
use crate::protocols::multi_party::dmz21::keygen::Parameters;
use crate::protocols::multi_party::dmz21::reshare::ReshareKeyPhase;
use crate::protocols::multi_party::dmz21::sign::SignPhase;
use crate::protocols::multi_party::dmz21::sign::SignPhaseOnline;
use crate::utilities::vss::map_share_to_new_params;
use crate::CU;
use crate::FE;
use crate::GE;
use anyhow::format_err;
use crossbeam_channel::*;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::secp256_k1::Secp256k1Point;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use curv::elliptic::curves::ECPoint;
use curv::elliptic::curves::ECScalar;
use curv::BigInt;
use rand::Rng;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

/// Local keygen phase
/// Input
///   index: self party id
///   params: contains share_counts and threshold
///   party_ids: all party ids
///   tx: sender of channel used to store message and sending type
///   rx: receiver of channel used to store message in msg_handler
/// Output
///   keys: key share generated from keygen phase
#[allow(unused_assignments)]
pub fn dmz_multi_keygen_local(
    index: String,
    params: Parameters,
    party_ids: Option<Vec<String>>,
    tx: Sender<Vec<u8>>,
    rx: Receiver<(String, Vec<u8>)>,
) -> String {
    let mut keygen = KeyGenPhase::new(index.clone(), params, &party_ids).unwrap();
    let begin_msg = keygen.process_begin().unwrap();
    let begin_msg_sending = bincode::serialize(&begin_msg)
        .map_err(|why| format_err!("bincode serialize error: {}", why))
        .unwrap();
    let mut key = "".to_string();
    tx.send(begin_msg_sending).unwrap();
    loop {
        let recv_msg = rx.recv().unwrap();
        let sending_msg = keygen.msg_handler(recv_msg.0, &recv_msg.1).unwrap();
        let sending_msg_bytes = bincode::serialize(&sending_msg)
            .map_err(|why| format_err!("bincode serialize error: {}", why))
            .unwrap();
        match sending_msg {
            SendingMessages::KeyGenSuccessWithResult(msg) => {
                key = msg;
                break;
            }
            _ => {}
        }
        tx.send(sending_msg_bytes).unwrap();
    }
    return key;
}

/// Local key resharing phase
/// Input:
///   index: self party id
///   party_ids: all party ids
///   new_party_ids: all new party ids
///   new_threshold: new threshold
///   tx: sender of channel used to store message and sending type
///   rx: receiver of channel used to store message in msg_handler
///   keys: Previous key share (DMZKeyX)
/// Output:
///   new_keys: key share generated from keygen phase

pub fn dmz_multi_reshare_local(
    index: String,
    party_ids: Vec<String>,
    new_party_ids: Vec<String>,
    new_threshold: usize,
    tx: Sender<Vec<u8>>,
    rx: Receiver<(String, Vec<u8>)>,
    keys: Option<String>, // The *old* keys (DMZKeyX as String)
) -> String {
    let mut reshare_phase =
        ReshareKeyPhase::new(index.clone(), party_ids, new_party_ids, new_threshold, keys).unwrap();
    //We start the protocol if we are the first one to enter:
    if reshare_phase.msgs.reshare_start_msgs.len() == 0 {
        let begin_msg = reshare_phase.process_begin().unwrap();

        let begin_msg_sending = bincode::serialize(&begin_msg)
            .map_err(|why| format_err!("bincode serialize error: {}", why))
            .unwrap();
        tx.send(begin_msg_sending).unwrap();
    }
    let mut new_keys = "".to_string();

    loop {
        let recv_msg = rx.recv().unwrap();

        let sending_msg = reshare_phase.msg_handler(recv_msg.0, &recv_msg.1).unwrap();

        let sending_msg_bytes = bincode::serialize(&sending_msg)
            .map_err(|why| format_err!("bincode serialize error: {}", why))
            .unwrap();
        match sending_msg {
            SendingMessages::ReshareKeySuccessWithResult(msg) => {
                new_keys = msg;
                break;
            }
            _ => {}
        }

        tx.send(sending_msg_bytes).unwrap();
    }

    return new_keys;
}

/// Local offline sign phase
/// Input
///   index: self party id
///   params: contains share_counts and threshold
///   subset: party ids of participants
///   tx: sender of channel used to store message and sending type
///   rx: receiver of channel used to store message in msg_handler
///   keys: key share used to sign
/// Output
///   offline_result: offline result used to online phase(each offline result only can used in one online phase)
#[allow(unused_assignments)]
pub fn dmz_multi_offline_sign_local(
    index: String,
    params: Parameters,
    subset: Vec<String>,
    tx: Sender<Vec<u8>>,
    rx: Receiver<(String, Vec<u8>)>,
    keys: String,
) -> String {
    let mut offline_sign = SignPhase::new(index.clone(), params, &subset, &keys).unwrap();
    let begin_msg = offline_sign.process_begin().unwrap();
    let begin_msg_sending = bincode::serialize(&begin_msg)
        .map_err(|why| format_err!("bincode serialize error: {}", why))
        .unwrap();
    let mut offline_result = "".to_string();
    tx.send(begin_msg_sending).unwrap();
    loop {
        let recv_msg = rx.recv().unwrap();
        let sending_msg = offline_sign.msg_handler(recv_msg.0, &recv_msg.1).unwrap();
        let sending_msg_bytes = bincode::serialize(&sending_msg)
            .map_err(|why| format_err!("bincode serialize error: {}", why))
            .unwrap();
        match sending_msg {
            SendingMessages::SignOfflineSuccessWithResult(msg) => {
                offline_result = msg;
                break;
            }
            _ => {}
        }
        tx.send(sending_msg_bytes).unwrap();
    }
    return offline_result;
}

/// Local online sign phase
/// Input
///   index: self party id
///   tx: sender of channel used to store message and sending type
///   rx: receiver of channel used to store message in msg_handler
///   offline_result: offline phase result
/// Output
///   keys: key share generated from keygen phase
#[allow(unused_assignments)]
pub fn dmz_multi_online_sign_local(
    tx: Sender<Vec<u8>>,
    rx: Receiver<(String, Vec<u8>)>,
    offline_result: String,
    message: Vec<u8>,
) -> String {
    let mut online_sign: SignPhaseOnline = SignPhaseOnline::new(&offline_result, message).unwrap();
    let begin_msg = online_sign.process_begin().unwrap();
    let begin_msg_sending = bincode::serialize(&begin_msg)
        .map_err(|why| format_err!("bincode serialize error: {}", why))
        .unwrap();
    let mut signature = "".to_string();
    tx.send(begin_msg_sending).unwrap();
    loop {
        let recv_msg = rx.recv().unwrap();
        let sending_msg = online_sign.msg_handler(recv_msg.0, &recv_msg.1).unwrap();
        let sending_msg_bytes = bincode::serialize(&sending_msg)
            .map_err(|why| format_err!("bincode serialize error: {}", why))
            .unwrap();
        match sending_msg {
            SendingMessages::SignOnlineSuccessWithResult(msg) => {
                signature = msg;
                break;
            }
            _ => {}
        }
        tx.send(sending_msg_bytes).unwrap();
    }
    return signature;
}

pub fn dmz_multi_keygen_local_test(params: Parameters, party_ids: Option<Vec<String>>) {
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

    let params1 = params.clone();
    let party_ids1 = party_ids.clone();
    let t = thread::spawn(move || loop {
        if let Ok(recv_message_str) = rx11.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "2".to_string() {
                            tx22.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "1".to_string() {
                            tx12.send(("1".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap();
                    tx12.send(("1".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx21.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("2".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx31.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("3".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        } else {
            break;
        }
    });
    let t1 = thread::spawn(move || {
        let key = dmz_multi_keygen_local("1".to_string(), params1, party_ids1, tx11, rx12);
    });
    let params2 = params.clone();
    let party_ids2 = party_ids.clone();
    let t2 = thread::spawn(move || {
        let key = dmz_multi_keygen_local("2".to_string(), params2, party_ids2, tx21, rx22);
    });
    let params3 = params.clone();
    let party_ids3 = party_ids.clone();
    let t3 = thread::spawn(move || {
        let key = dmz_multi_keygen_local("3".to_string(), params3, party_ids3, tx31, rx32);
    });

    t.join().unwrap();
    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();
}
pub fn dmz_multi_sign_local_test(
    params: Parameters,
    subset: Vec<String>,
    message: Vec<u8>,
    party_ids: Option<Vec<String>>,
) {
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

    let params1 = params.clone();
    let subset1 = subset.clone();
    let party_ids1 = party_ids.clone();
    let t = thread::spawn(move || loop {
        if let Ok(recv_message_str) = rx11.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "2".to_string() {
                            tx22.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "1".to_string() {
                            tx12.send(("1".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap();
                    tx12.send(("1".to_string(), msg)).unwrap();
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap();
                    tx12.send(("1".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx21.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("2".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx31.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("3".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg)).unwrap();
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        } else {
            break;
        }
    });
    let message1 = message.clone();
    let t1 = thread::spawn(move || {
        let key = dmz_multi_keygen_local(
            "1".to_string(),
            params1.clone(),
            party_ids1,
            tx11.clone(),
            rx12.clone(),
        );
        let offline_result1 = dmz_multi_offline_sign_local(
            "1".to_string(),
            params1,
            subset1,
            tx11.clone(),
            rx12.clone(),
            key,
        );
        let signature1 = dmz_multi_online_sign_local(tx11, rx12, offline_result1, message1);
    });
    let params2 = params.clone();
    let subset2 = subset.clone();
    let party_ids2 = party_ids.clone();
    let message2 = message.clone();
    let t2 = thread::spawn(move || {
        let key = dmz_multi_keygen_local(
            "2".to_string(),
            params2.clone(),
            party_ids2,
            tx21.clone(),
            rx22.clone(),
        );
        let offline_result2 = dmz_multi_offline_sign_local(
            "2".to_string(),
            params2,
            subset2,
            tx21.clone(),
            rx22.clone(),
            key,
        );
        let siganture2 = dmz_multi_online_sign_local(tx21, rx22, offline_result2, message2);
    });
    let params3 = params.clone();
    let subset3 = subset.clone();
    let party_ids3 = party_ids.clone();
    let message3 = message.clone();
    let t3 = thread::spawn(move || {
        let key = dmz_multi_keygen_local(
            "3".to_string(),
            params3.clone(),
            party_ids3,
            tx31.clone(),
            rx32.clone(),
        );
        let offline_result3 = dmz_multi_offline_sign_local(
            "3".to_string(),
            params3,
            subset3,
            tx31.clone(),
            rx32.clone(),
            key,
        );
        let signature3 = dmz_multi_online_sign_local(tx31, rx32, offline_result3, message3);
    });

    t.join().unwrap();
    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();
}

///
/// cargo test --package multi-party-ecdsa --lib --release -- protocols::multi_party::dmz21::local
/// cargo test --package multi-party-ecdsa --lib --release -- protocols::multi_party::dmz21::local::local_ecdsa_keygen
/// cargo test --package multi-party-ecdsa --lib --release -- protocols::multi_party::dmz21::local::local_ecdsa_sign
///

#[test]
fn local_ecdsa_keygen() {
    let params = Parameters {
        threshold: 1,
        share_count: 3,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let start = time::now();
    dmz_multi_keygen_local_test(params.clone(), Some(party_ids));
}

#[test]
fn local_ecdsa_sign() {
    let params = Parameters {
        threshold: 1,
        share_count: 3,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let subset = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let message_bytes = "1234567890abcdef1234567890abcdef".as_bytes().to_vec();
    let start = time::now();
    dmz_multi_sign_local_test(params, subset, message_bytes, Some(party_ids));
}

#[test]
fn test_reshare_key_phase_new_participant() {
    let reshare_key_phase = ReshareKeyPhase::new(
        "4".to_string(),
        vec!["1".to_string(), "2".to_string(), "3".to_string()],
        vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
        ],
        2,
        None, // New participant has no keys.
    );
    assert!(reshare_key_phase.is_ok());
    assert!(reshare_key_phase.unwrap().is_new_participant);
}

#[test]
fn test_reshare_key_phase_existing_participant_no_keys() {
    let reshare_key_phase = ReshareKeyPhase::new(
        "1".to_string(),
        vec!["1".to_string(), "2".to_string(), "3".to_string()],
        vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
        ],
        2,
        None, // Existing participant *must* provide keys.
    );
    assert!(reshare_key_phase.is_err()); // Should fail because keys are missing.
}



#[test]
fn test_reshare_key_phase_invalid_index() {
    // Simulate a KeyGenPhase to get valid keys.
    let keys = r#"{"index":"1","participants":["1","2","0"],"pubkey":{"pk":["38b91186e5d987496ffb7b9cb07a35190d8efdbd3d6b4e6d8765c94af332190","ceb0e48420b5a96165781b874d14d0d44dca3f60d6b2cbf7ac2389e7f2e8e94c"],"share_pks":{"1":["7907eb5c547849ff49fac97daa74637b88e04bdc02d788127994679cdc5b56f","820c5223618560d9fbb42b2c8e6f114b937ccc8f6901d257a315f74ef2ce1923"],"2":["15c221cd9cd4745f58d323c21c6e9607c6283caaf2afb5ee0652c2bfd45c2961","72879ebb13efef2569431390a1f8958703792db8a00a8ddb5ec8f0ab5f120cff"],"0":["38b91186e5d987496ffb7b9cb07a35190d8efdbd3d6b4e6d8765c94af332190","ceb0e48420b5a96165781b874d14d0d44dca3f60d6b2cbf7ac2389e7f2e8e94c"]}},"privkey":{"cl_sk":"55d2509f0c08d5bee44830f3f01f3641d9c8b04514b3d97e20c463970ed3a1d5c75e1d938e22612bc27e576fba9709ab335277de8b8c7ed8a498d6eda2b3b62934ad6fde3d76891fa81a687099447e5bd125f0062428d61f98115b41d8bfb6d0fde301431ec7b120b9bf26a3e197b42f8ae8a1cfbea2fc4ac4d59c965c771b5212a2367c0ab612a6416914e43","ec_sk":"4f2100d3042403261098c5caac9da7576fb45244c7fba1eb89382b3085934f9a","share_sk":"552d560f9ba4a99192eb2c1b66500bc3c1bd9c001f0da47f8fb491f38d6026ab"}}"#;
    // "4" is not in the original party_ids.
    let reshare_key_phase = ReshareKeyPhase::new(
        "4".to_string(),
        vec!["1".to_string(), "2".to_string(), "3".to_string()],
        vec!["1".to_string(), "2".to_string(), "4".to_string()],
        2,
        Some(keys.to_string()),
    );
    assert!(reshare_key_phase.is_err());
}

#[test]
fn test_reshare_key_phase_new_participant_with_keys() {
    // 1. Simulate Key Generation (simplified - we just need *some* valid key data)
    let params = Parameters {
        threshold: 1,
        share_count: 3,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

            // Helper function for keygen routing (in the SAME test function now)
    fn generate_router_keygen(
        rx11: crossbeam::channel::Receiver<Vec<u8>>,
        tx12: crossbeam::channel::Sender<(String, Vec<u8>)>,
        rx21: crossbeam::channel::Receiver<Vec<u8>>,
        tx22: crossbeam::channel::Sender<(String, Vec<u8>)>,
        rx31: crossbeam::channel::Receiver<Vec<u8>>,
        tx32: crossbeam::channel::Sender<(String, Vec<u8>)>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || loop {
            //Party 1
            if let Ok(recv_message_str) = rx11.recv() {
                let recv_message: SendingMessages = bincode::deserialize(&recv_message_str).unwrap();
                match recv_message {
                    SendingMessages::P2pMessage(msg) => {
                        for (key, value) in msg {
                            if key == "2".to_string() {
                                tx22.send(("1".to_string(), value.clone())).unwrap();
                            }
                            if key == "3".to_string() {
                                tx32.send(("1".to_string(), value.clone())).unwrap();
                            }
                        }
                    }
                    SendingMessages::BroadcastMessage(msg)  => {
                        tx22.send(("1".to_string(), msg.clone())).unwrap();
                        tx32.send(("1".to_string(), msg.clone())).unwrap();
                        tx12.send(("1".to_string(), msg.clone())).unwrap();

                    }
                    _ => {}
                }
            }

            //Party 2
            if let Ok(recv_message_str) = rx21.recv() {
                let recv_message: SendingMessages = bincode::deserialize(&recv_message_str).unwrap();
                match recv_message {
                    SendingMessages::P2pMessage(msg) => {
                        for (key, value) in msg {
                            if key == "1".to_string() {
                                tx12.send(("2".to_string(), value.clone())).unwrap();
                            }
                            if key == "3".to_string() {
                                tx32.send(("2".to_string(), value.clone())).unwrap();
                            }
                        }
                    }
                    SendingMessages::BroadcastMessage(msg) => {
                        tx12.send(("2".to_string(), msg.clone())).unwrap();
                        tx32.send(("2".to_string(), msg.clone())).unwrap();
                        tx22.send(("2".to_string(), msg.clone())).unwrap();

                    }
                    _ => {}
                }
            }

            // Party 3
            if let Ok(recv_message_str) = rx31.recv() {
                let recv_message = bincode::deserialize(&recv_message_str)
                    .map_err(|why| format_err!("bincode deserialize error: {}", why))
                    .unwrap();
                match recv_message {
                    SendingMessages::P2pMessage(msg) => {
                        for (key, value) in msg {
                            if key == "1".to_string() {
                                tx12.send(("3".to_string(), value.clone())).unwrap();
                            }
                            if key == "2".to_string() {
                                tx22.send(("3".to_string(), value.clone())).unwrap();
                            }
                        }
                    }
                    SendingMessages::BroadcastMessage(msg) => {
                        tx12.send(("3".to_string(), msg.clone())).unwrap();
                        tx22.send(("3".to_string(), msg.clone())).unwrap();
                        tx32.send(("3".to_string(), msg.clone())).unwrap();

                    }
                    _ => {}
                }
            } else { // Important: exit the loop when one channel closes
                break;
            }
        })
    }

        // Router for keygen
    let router = generate_router_keygen(rx11, tx12, rx21, tx22, rx31, tx32);

    let t1 = thread::spawn({
        let party_ids = party_ids.clone();
        let params = params.clone();
        move || dmz_multi_keygen_local("1".to_string(), params, Some(party_ids), tx11, rx12)
    });
    let t2 = thread::spawn({
        let party_ids = party_ids.clone();
        let params = params.clone();
        move || dmz_multi_keygen_local("2".to_string(), params, Some(party_ids), tx21, rx22)
    });
    let t3 = thread::spawn({
        let party_ids = party_ids.clone();
        let params = params.clone();
        move || dmz_multi_keygen_local("3".to_string(), params, Some(party_ids), tx31, rx32)
    });

    let keys1 = t1.join().expect("Keygen 1 failed");
    let keys2 = t2.join().expect("keygen 2 failed"); // Ensure all finish.
    let keys3 = t3.join().expect("keygen 3 failed");
    router.join().expect("router failed");

    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();
    let (tx41, rx41) = unbounded::<Vec<u8>>();
    let (tx42, rx42) = unbounded::<(String, Vec<u8>)>();

    let router = generate_router_4(rx11, tx12, rx21, tx22, rx31, tx32, rx41, tx42);

    let _party_ids = party_ids;
    let _new_party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()  ];
    let new_threshold = 2;

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();

    let t1 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "1".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx11,
            rx12,
            Some(keys1),
        )
    });

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t2 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "2".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx21,
            rx22,
            Some(keys2),
        )
    });
    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t3 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "3".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx31,
            rx32,
            Some(keys3),
        )
    });

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t4 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "4".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx41,
            rx42,
            None,
        )
    });

    router.join().unwrap();
    let reshare_result_1 = t1.join().unwrap();
    let reshare_result_2 = t2.join().unwrap();
    let reshare_result_3 = t3.join().unwrap();
    let reshare_result_4 = t4.join().unwrap();
    


   
}


#[test]
fn test_reshare_key_phase_remove_participant() {
    // 1. KeyGen Phase (3 participants)
    let params = Parameters {
        threshold: 2,
        share_count: 4,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string(), "4".to_string()];
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();
    let (tx41, rx41) = unbounded::<Vec<u8>>();
    let (tx42, rx42) = unbounded::<(String, Vec<u8>)>();

    //simulate message exchanging
    let t = generate_router_4(rx11, tx12, rx21, tx22, rx31, tx32, rx41, tx42);
    let _party_ids = party_ids.clone();
    let _params = params.clone();
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t1 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "1".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx11,
            rx12,
        )
    });
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t2 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "2".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx21,
            rx22,
        )
    });
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t3 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "3".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx31,
            rx32,
        )
    });

    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t4 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "4".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx41,
            rx42,
        )
    });
    t.join().unwrap();
    let keygen_result_1 = t1.join().unwrap();
    let keygen_result_2 = t2.join().unwrap();
    let keygen_result_3 = t3.join().unwrap();
    let keygen_result_4 = t4.join().unwrap();




    




    let new_party_ids = vec!["1".to_string(), "2".to_string(), "4".to_string()];
    let new_threshold = 1;



    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx41, rx41) = unbounded::<Vec<u8>>();
    let (tx42, rx42) = unbounded::<(String, Vec<u8>)>();

    //simulate message exchanging
    let t = generate_router(rx11, tx12, rx21, tx22, rx41, tx42);
    // let _party_ids = _party_ids.clone();
    let _new_party_ids = new_party_ids.clone();
    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();

    let t1 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "1".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx11,
            rx12,
            Some(keygen_result_1),
        )
    });

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t2 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "2".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx21,
            rx22,
            Some(keygen_result_2),
        )
    });

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t4 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "4".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx41,
            rx42,
            Some(keygen_result_4),
        )
    });

    t.join().unwrap();
    let reshare_result_1 = t1.join().unwrap();
    let reshare_result_2 = t2.join().unwrap();
    let reshare_result_4 = t4.join().unwrap();





    let reshare1: DMZKeyX = serde_json::from_str(&reshare_result_1).unwrap();
    let reshare2: DMZKeyX = serde_json::from_str(&reshare_result_2).unwrap();
    let reshare4: DMZKeyX = serde_json::from_str(&reshare_result_4).unwrap();


    // Check participant lists.
    assert_eq!(reshare1.participants, _new_party_ids);
    assert_eq!(reshare2.participants, _new_party_ids);
    assert_eq!(reshare4.participants, _new_party_ids);

    // check dleq proof of participant 4
    let proof = reshare4.clone().privkey.share_sk;
    let proof_fe = FE::from_bigint(&BigInt::from_hex(&proof).unwrap());
    let d_log_proof = DLogProof::<CU, sha2::Sha256>::prove(&proof_fe);
    assert!(DLogProof::<CU, sha2::Sha256>::verify(&d_log_proof).is_ok());


    fn to_fe(hex_str: &str) -> FE {
        let bigint = BigInt::from_hex(hex_str).unwrap();
        FE::from_bigint(&bigint)
    }

    let (x_hex, y_hex) = (&reshare1.pubkey.pk[0], &reshare1.pubkey.pk[1]); // Adjust indexing based on your structure
    let x_bigint = BigInt::from_hex(x_hex).expect("invalid x coordinate");
    let y_bigint = BigInt::from_hex(y_hex).expect("invalid y coordinate");
    let declared_pk = Secp256k1Point::from_coords(&x_bigint, &y_bigint)
        .expect("failed to create point from coordinates");
    
    
    fn lagrange_coeff(index: &str, S: &[&str]) -> FE {
        let xi = BigInt::from_str_radix(index, 16).unwrap();
        let S_bigint: Vec<BigInt> = S.iter().map(|id| BigInt::from_str_radix(id, 16).unwrap()).collect();
        map_share_to_new_params(xi, &S_bigint)
    }
    
    let S = vec!["1", "2", "4"];
    let mut reconstructed_sk = FE::zero();

    for &index in &S {
        let share = if index == "1" {
            to_fe(&reshare1.privkey.share_sk)
        } else if index == "2" {
            to_fe(&reshare2.privkey.share_sk)
        } else {
            to_fe(&reshare4.privkey.share_sk)
        };

        let l_i = lagrange_coeff(index, &S); // make sure lagrange_coeff also returns FE
        reconstructed_sk = reconstructed_sk + (share * l_i);
    }

    // Now `reconstructed_sk` is an FE
    let computed_pk = Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&reconstructed_sk.to_bigint()));
    assert_eq!(computed_pk, declared_pk);





    // sign

    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx41, rx41) = unbounded::<Vec<u8>>();
    let (tx42, rx42) = unbounded::<(String, Vec<u8>)>();

    //simulate message exchanging
    let t = generate_router(rx11, tx12, rx21, tx22, rx41, tx42);
    // let _party_ids = _party_ids.clone();
    let new_party_ids = vec!["1".to_string(), "2".to_string(), "4".to_string()];
    let _new_party_ids = new_party_ids.clone();
    
    
    let _params = Parameters {
        threshold: new_threshold,
        share_count:3
    };
    let _subset = vec!["1".to_string(),"2".to_string(), "4".to_string()];
    let _message = "1234567890abcdef1234567890abcdef".as_bytes().to_vec();

    let params = _params.clone();
    let subset = _subset.clone();
    let message = _message.clone();
    let t1 = thread::spawn(move || {
        let offline_result1 = dmz_multi_offline_sign_local(
            "1".to_string(),
            params,
            subset,
            tx11.clone(),
            rx12.clone(),
            reshare_result_1,
        );

        let signature1 = dmz_multi_online_sign_local(tx11, rx12, offline_result1, message);

    });

    
    
    let params = _params.clone();
    let subset = _subset.clone();
    let message = _message.clone();

    let t2 = thread::spawn(move || {
        let offline_result2 = dmz_multi_offline_sign_local(
            "2".to_string(),
            params,
            subset,
            tx21.clone(),
            rx22.clone(),
            reshare_result_2,
        );

        let signature2 = dmz_multi_online_sign_local(tx21, rx22, offline_result2, message);

    });

    
    
    let params = _params.clone();
    let subset = _subset.clone();
    let message = _message.clone();
    let t4 = thread::spawn(move || {

        let offline_result4 = dmz_multi_offline_sign_local(
            "4".to_string(),
            params,
            subset,
            tx41.clone(),
            rx42.clone(),
            reshare_result_4,
        );

        let signature4 = dmz_multi_online_sign_local(tx41, rx42, offline_result4, message);

    });

    t.join().unwrap();
    t1.join().unwrap();
    t2.join().unwrap();
    t4.join().unwrap();
























}


// This test function now includes simulation of message passing.
#[test]
fn test_full_reshare_add_participant() {
    // 1. KeyGen Phase (3 participants)
    let params = Parameters {
        threshold: 1,
        share_count: 3,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

    //simulate message exchanging
    let t = thread::spawn(move || loop {
        if let Ok(recv_message_str) = rx11.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "2".to_string() {
                            tx22.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "1".to_string() {
                            tx12.send(("1".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap();
                    tx12.send(("1".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx21.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("2".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx31.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("3".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        } else {
            break;
        }
    });
    let _party_ids = party_ids.clone();
    let _params = params.clone();
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t1 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "1".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx11,
            rx12,
        )
    });
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t2 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "2".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx21,
            rx22,
        )
    });
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t3 = std::thread::spawn(move || {
        dmz_multi_keygen_local(
            "3".to_string(),
            params.clone(),
            Some(party_ids.clone()),
            tx31,
            rx32,
        )
    });

    t.join().unwrap();
    let keygen_result_1 = t1.join().unwrap();
    let keygen_result_2 = t2.join().unwrap();
    let keygen_result_3 = t3.join().unwrap();

    let key1: DMZKeyX = serde_json::from_str(&keygen_result_1).unwrap();
    let key2: DMZKeyX = serde_json::from_str(&keygen_result_2).unwrap();
    let key3: DMZKeyX = serde_json::from_str(&keygen_result_3).unwrap();

    // 2. Reshare Phase (add participant "4", keeping "1", "2", remove "3")
    let new_party_ids = vec!["1".to_string(), "2".to_string(), "4".to_string()];
    let new_threshold = 1;

    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx41, rx41) = unbounded::<Vec<u8>>();
    let (tx42, rx42) = unbounded::<(String, Vec<u8>)>();

    //simulate message exchanging
    let t = generate_router(rx11, tx12, rx21, tx22, rx41, tx42);
    // let _party_ids = _party_ids.clone();
    let _new_party_ids = new_party_ids.clone();
    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();

    let t1 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "1".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx11,
            rx12,
            Some(keygen_result_1),
        )
    });

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t2 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "2".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx21,
            rx22,
            Some(keygen_result_2),
        )
    });

    let party_ids = _party_ids.clone();
    let new_party_ids = _new_party_ids.clone();
    let t4 = thread::spawn(move || {
        dmz_multi_reshare_local(
            "4".to_string(),
            party_ids.clone(),
            new_party_ids.clone(),
            new_threshold,
            tx41,
            rx42,
            None,
        )
    });

    t.join().unwrap();
    let reshare_result_1 = t1.join().unwrap();
    let reshare_result_2 = t2.join().unwrap();
    let reshare_result_4 = t4.join().unwrap();





    let reshare1: DMZKeyX = serde_json::from_str(&reshare_result_1).unwrap();
    let reshare2: DMZKeyX = serde_json::from_str(&reshare_result_2).unwrap();
    let reshare4: DMZKeyX = serde_json::from_str(&reshare_result_4).unwrap();

    // 3. Verify Results
    // Check public key consistency.
    assert_eq!(key1.pubkey.pk, key2.pubkey.pk);
    assert_eq!(key1.pubkey.pk, key3.pubkey.pk);
    assert_eq!(reshare1.pubkey.pk, reshare2.pubkey.pk);
    assert_eq!(reshare1.pubkey.pk, key1.pubkey.pk); // Reshare should preserve pubkey.
    assert_eq!(reshare4.pubkey.pk, key1.pubkey.pk);

    // Check participant lists.
    assert_eq!(reshare1.participants, _new_party_ids);
    assert_eq!(reshare2.participants, _new_party_ids);
    assert_eq!(reshare4.participants, _new_party_ids);

    // check dleq proof of participant 4
    let proof = reshare4.clone().privkey.share_sk;
    let proof_fe = FE::from_bigint(&BigInt::from_hex(&proof).unwrap());
    let d_log_proof = DLogProof::<CU, sha2::Sha256>::prove(&proof_fe);
    assert!(DLogProof::<CU, sha2::Sha256>::verify(&d_log_proof).is_ok());


    fn to_fe(hex_str: &str) -> FE {
        let bigint = BigInt::from_hex(hex_str).unwrap();
        FE::from_bigint(&bigint)
    }

    let (x_hex, y_hex) = (&reshare1.pubkey.pk[0], &reshare1.pubkey.pk[1]); // Adjust indexing based on your structure
    let x_bigint = BigInt::from_hex(x_hex).expect("invalid x coordinate");
    let y_bigint = BigInt::from_hex(y_hex).expect("invalid y coordinate");
    let declared_pk = Secp256k1Point::from_coords(&x_bigint, &y_bigint)
        .expect("failed to create point from coordinates");
    
    
    fn lagrange_coeff(index: &str, S: &[&str]) -> FE {
        let xi = BigInt::from_str_radix(index, 16).unwrap();
        let S_bigint: Vec<BigInt> = S.iter().map(|id| BigInt::from_str_radix(id, 16).unwrap()).collect();
        map_share_to_new_params(xi, &S_bigint)
    }
    
    let S = vec!["1", "2", "4"];
    let mut reconstructed_sk = FE::zero();

    for &index in &S {
        let share = if index == "1" {
            to_fe(&reshare1.privkey.share_sk)
        } else if index == "2" {
            to_fe(&reshare2.privkey.share_sk)
        } else {
            to_fe(&reshare4.privkey.share_sk)
        };

        let l_i = lagrange_coeff(index, &S); // make sure lagrange_coeff also returns FE
        reconstructed_sk = reconstructed_sk + (share * l_i);
    }

    // Now `reconstructed_sk` is an FE
    let computed_pk = Secp256k1Point::generator().scalar_mul(&Secp256k1Scalar::from_bigint(&reconstructed_sk.to_bigint()));
    assert_eq!(computed_pk, declared_pk);





    // sign

    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx41, rx41) = unbounded::<Vec<u8>>();
    let (tx42, rx42) = unbounded::<(String, Vec<u8>)>();

    //simulate message exchanging
    let t = generate_router(rx11, tx12, rx21, tx22, rx41, tx42);
    // let _party_ids = _party_ids.clone();
    let new_party_ids = vec!["1".to_string(), "2".to_string(), "4".to_string()];
    let _new_party_ids = new_party_ids.clone();
    
    
    let _params = Parameters {
        threshold: new_threshold,
        share_count:3
    };
    let _subset = vec!["1".to_string(),"2".to_string(), "4".to_string()];
    let _message = "1234567890abcdef1234567890abcdef".as_bytes().to_vec();

    let params = _params.clone();
    let subset = _subset.clone();
    let message = _message.clone();
    let t1 = thread::spawn(move || {
        let offline_result1 = dmz_multi_offline_sign_local(
            "1".to_string(),
            params,
            subset,
            tx11.clone(),
            rx12.clone(),
            reshare_result_1,
        );
        let signature1 = dmz_multi_online_sign_local(tx11, rx12, offline_result1, message);
    });

    
    
    let params = _params.clone();
    let subset = _subset.clone();
    let message = _message.clone();

    let t2 = thread::spawn(move || {
        let offline_result2 = dmz_multi_offline_sign_local(
            "2".to_string(),
            params,
            subset,
            tx21.clone(),
            rx22.clone(),
            reshare_result_2,
        );
        let signature2 = dmz_multi_online_sign_local(tx21, rx22, offline_result2, message);
    });

    
    
    let params = _params.clone();
    let subset = _subset.clone();
    let message = _message.clone();
    let t4 = thread::spawn(move || {

        let offline_result4 = dmz_multi_offline_sign_local(
            "4".to_string(),
            params,
            subset,
            tx41.clone(),
            rx42.clone(),
            reshare_result_4,
        );
        let signature4 = dmz_multi_online_sign_local(tx41, rx42, offline_result4, message);
    });

    t.join().unwrap();
    t1.join().unwrap();
    t2.join().unwrap();
    t4.join().unwrap();

    


    

    //    t.join().unwrap(); // Wait for all threads
}

fn generate_router(rx11: Receiver<Vec<u8>>, tx12: Sender<(String, Vec<u8>)>, rx21: Receiver<Vec<u8>>, tx22: Sender<(String, Vec<u8>)>, rx41: Receiver<Vec<u8>>, tx42: Sender<(String, Vec<u8>)>) -> thread::JoinHandle<()> {
    let t = thread::spawn(move || loop {
        if let Ok(recv_message_str) = rx11.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "2".to_string() {
                            tx22.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "1".to_string() {
                            tx12.send(("1".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx42.send(("1".to_string(), msg.clone())).unwrap();
                    tx12.send(("1".to_string(), msg)).unwrap();
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("1".to_string(), msg.clone())).unwrap();
                    tx42.send(("1".to_string(), msg.clone())).unwrap();
                    tx22.send(("1".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx21.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("2".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx42.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx42.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        }
        if let Ok(recv_message_str) = rx41.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("4".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("4".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("4".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("4".to_string(), msg.clone())).unwrap();
                    tx22.send(("4".to_string(), msg.clone())).unwrap();
                    tx42.send(("4".to_string(), msg)).unwrap();
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("4".to_string(), msg.clone())).unwrap();
                    tx42.send(("4".to_string(), msg.clone())).unwrap();
                    tx22.send(("4".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        } else {
            break;
        }
    });
    t
}

fn generate_sender_receiver_map(indexes:Vec<String>) -> HashMap<String, ((Sender<(String, Vec<u8>)>, Receiver<(String, Vec<u8>)>), (Sender<Vec<u8>>, Receiver<Vec<u8>>))> {
    let mut sender_receiver_map: HashMap<String, ((Sender<(String, Vec<u8>)>, Receiver<(String, Vec<u8>)>), (Sender<Vec<u8>>, Receiver<Vec<u8>>))> = HashMap::new();
    for i in indexes {
        let (tx, rx) = unbounded::<(String, Vec<u8>)>();
        let (tx2, rx2) = unbounded::<Vec<u8>>();
        sender_receiver_map.insert(i.to_string(), ((tx, rx), (tx2, rx2)));
    }
    sender_receiver_map
}


fn generate_multi_router(sender_receiver_map: HashMap<String, ((Sender<(String, Vec<u8>)>, Receiver<(String, Vec<u8>)>), (Sender<Vec<u8>>, Receiver<Vec<u8>>))> ) -> thread::JoinHandle<()> {
   
    let t = thread::spawn(move || loop {
        for i in sender_receiver_map.keys() {
            if let Ok(recv_message_str) = sender_receiver_map[&i.to_string()].1.1.recv() {
                let recv_message = bincode::deserialize(&recv_message_str)
                    .map_err(|why| format_err!("bincode deserialize error: {}", why))
                    .unwrap();
                match recv_message {
                    SendingMessages::P2pMessage(msg) => {
                        for (key, value) in msg {
                            if sender_receiver_map.contains_key(&key){
                                sender_receiver_map[&key].0.0.send((i.to_string(), value.clone())).unwrap();
                            }
                        }
                    }
                    SendingMessages::BroadcastMessage(msg) => {
                        for j in sender_receiver_map.keys() {
                            if sender_receiver_map.contains_key(&j.to_string()){
                                sender_receiver_map[&j.to_string()].0.0.send((i.to_string(), msg.clone())).unwrap();
                            }

                        }
                    }
                    SendingMessages::SubsetMessage(msg) => {
                        for j in sender_receiver_map.keys() {
                            if sender_receiver_map.contains_key(&j.to_string()){
                                sender_receiver_map[&j.to_string()].0.0.send((i.to_string(), msg.clone())).unwrap();
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }

    });

    t
}

 #[test]
 fn test_4_parties() {
    let start = time::now();
    let n: usize = 5;
    let perc = 0.85f32;
    let t: usize = (perc * n as f32).ceil() as usize;
    let params = Parameters {
        threshold: if t < n - 1 {t} else {n -2},
        share_count: n,
    };

    println!("Params: {:?}", params);

    let party_ids: Vec<String> = (1..n+1).into_iter().map(|i| i.to_string()).collect();

    
    let sender_receiver_map = generate_sender_receiver_map(party_ids.clone());
    let t = generate_multi_router(sender_receiver_map.clone());
    let _party_ids = party_ids.clone();
    let _params = params.clone();
    let mut keygen_threads = BTreeMap::new();
    for i in 1..n+1 {
        let tx = sender_receiver_map[&i.to_string()].1.0.clone();
        let rx = sender_receiver_map[&i.to_string()].0.1.clone();
        let params = _params.clone();
        let party_ids = _party_ids.clone();
        let t = thread::spawn(move || {
            dmz_multi_keygen_local(
                i.to_string(),
                params.clone(),
                Some(party_ids.clone()),
                tx,
                rx,
            )
        });
        keygen_threads.insert(i.to_string(), t);
    }
    
    // let res = t.join().unwrap();
    // println!("Res: {:?}k", res);
    let keygen_results: BTreeMap<String, String> = keygen_threads.into_iter().map(|(id, t)| (id, t.join().unwrap())).collect();
    // let keys: Vec<DMZKeyX> = keygen_results.into_iter().map(|r| serde_json::from_str(&r).unwrap()).collect();

    let end = time::now();
    let elapsed = end - start;
    println!("Elapsed time Keygen: {:?}", elapsed);

    let start = time::now();

    // 2. Reshare Phase (remove a random participant and add a new participant with id n + 1)
    // new_party_ids will be the same as party_ids, but with the random participant removed and n + 1 added.
    let mut new_party_ids = _party_ids.clone();
    new_party_ids.pop();
    new_party_ids.push((n+1).to_string());


    

    let new_threshold = _params.threshold;
    let sender_receiver_map = generate_sender_receiver_map(new_party_ids.clone());
    let t = generate_multi_router(sender_receiver_map.clone());
    let _new_party_ids = new_party_ids.clone();
    let mut reshare_threads = BTreeMap::new();
    let _keygen_results = keygen_results.clone();

    for i in new_party_ids {
        let tx = sender_receiver_map[&i.to_string()].1.0.clone();
        let rx = sender_receiver_map[&i.to_string()].0.1.clone();
        let party_ids_clone = _party_ids.clone();
        let new_party_ids_clone = _new_party_ids.clone();
        let keygen_result = _keygen_results.get(&i.clone()).cloned();
        let id = i.clone();
        let t = thread::spawn(move || {
            dmz_multi_reshare_local(
                i.clone(),
                party_ids_clone,
                new_party_ids_clone,
                new_threshold,
                tx,
                rx,
                keygen_result,
            )
        });
        reshare_threads.insert(id.clone(), t);
    }
    // t.join().unwrap();
    let reshare_results: BTreeMap<String, String> = reshare_threads.into_iter().map(|(id,t)| (id, t.join().unwrap())).collect();

    let end = time::now();
    let elapsed = end - start;

    println!("Elapsed time Reshare: {:?}", elapsed);
    let tmp_key: DMZKeyX = serde_json::from_str(&_keygen_results.get("1").unwrap()).unwrap();




    let pubkey = tmp_key.pubkey.pk.clone();
    for (id, _) in reshare_results.clone() {
        let reshare: DMZKeyX = serde_json::from_str(&reshare_results.get(&id).unwrap()).unwrap();
        assert_eq!(pubkey, reshare.pubkey.pk.clone());
        if _keygen_results.contains_key(&id) {
            let key: DMZKeyX = serde_json::from_str(&_keygen_results.get(&id).unwrap()).unwrap();
            // Check public key consistency.
            assert_eq!(key.pubkey.pk, reshare.pubkey.pk);

            // Check the pubkey is the same as the one in the keygen phase.
            assert_eq!(key.pubkey.pk, pubkey);
        }
        // Check participant lists.
        assert_eq!(reshare.participants, _new_party_ids);
    }


    // 3. Do a sign offline measuring time
    let _params = Parameters {
        threshold: new_threshold,
        share_count: n,
    };

    let _subset = _new_party_ids.clone();
    let _message = "1234567890abcdef1234567890abcdef".as_bytes().to_vec();

    let start = time::now();

    let mut sign_threads = BTreeMap::new();
    for i in _new_party_ids.clone() {
        let tx = sender_receiver_map[&i.to_string()].1.0.clone();
        let rx = sender_receiver_map[&i.to_string()].0.1.clone();
        let reshare_result = reshare_results.get(&i).cloned();

        assert!(reshare_result.is_some());
        let reshare_result = reshare_result.unwrap();
        let params = _params.clone();
        let subset = _subset.clone();
        let message = _message.clone();

        let id = i.clone();
    
        let t = thread::spawn(move || {
            let offline_result = dmz_multi_offline_sign_local(
                i.clone(),
                params,
                subset,
                tx.clone(),
                rx.clone(),
                reshare_result,
            );
            offline_result
        });
        sign_threads.insert(id, t);
    }

    let sign_results: BTreeMap<String, String> = sign_threads.into_iter().map(|(id, t)| (id, t.join().unwrap())).collect();
    // estimate the time taken:
    let end = time::now();
    let elapsed = end - start;
    println!("Elapsed time Offline: {:?}", elapsed);

    // 4. Do a sign online measuring time
    let start = time::now();
    let mut sign_threads = BTreeMap::new();
    for i in _new_party_ids.clone() {
        let tx = sender_receiver_map[&i.to_string()].1.
        0.clone();
        let rx = sender_receiver_map[&i.to_string()].0.1.clone();
        let offline_result = sign_results.get(&i).cloned();
        assert!(offline_result.is_some());
        let id = i.clone();

        let offline_result = offline_result.unwrap();
        let message = _message.clone();
        let t = thread::spawn(move || {
            dmz_multi_online_sign_local(tx, rx, offline_result, message)
        });
        sign_threads.insert(id, t);

    }

    let sign_results: BTreeMap<String, String> = sign_threads.into_iter().map(|(id, t)| (id, t.join().unwrap())).collect();
    // estimate the time taken:
    let end = time::now();
    let elapsed = end - start;
    println!("Elapsed time Online: {:?}", elapsed);

    // // 5. Verify the signature
    // let mut sigs = BTreeMap::new();
    // for (id, sig) in sign_results.clone() {
    //     let sig = bincode::deserialize(&sig).unwrap();
    //     sigs.insert(id, sig);
    // }

    // let mut sigs: BTreeMap<String, Vec<u8>> = sigs.into_iter().map(|(id, sig)| (id, sig)).collect();

    


}




fn generate_router_4(
    rx11: Receiver<Vec<u8>>,
    tx12: Sender<(String, Vec<u8>)>,
    rx21: Receiver<Vec<u8>>,
    tx22: Sender<(String, Vec<u8>)>,
    rx31: Receiver<Vec<u8>>, // Added rx31
    tx32: Sender<(String, Vec<u8>)>, // Added tx32
    rx41: Receiver<Vec<u8>>,
    tx42: Sender<(String, Vec<u8>)>,
) -> thread::JoinHandle<()> {
    let t = thread::spawn(move || loop {
        // Handle messages from party 1
        if let Ok(recv_message_str) = rx11.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "2".to_string() {
                            tx22.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() { // Added 3
                            tx32.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "1".to_string() {
                            tx12.send(("1".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("1".to_string(), msg.clone())).unwrap();
                    tx12.send(("1".to_string(), msg)).unwrap();
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("1".to_string(), msg.clone())).unwrap();
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("1".to_string(), msg.clone())).unwrap();
                }
                _ => {}
            }
        }

        // Handle messages from party 2
        if let Ok(recv_message_str) = rx21.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() { // Added 3
                            tx32.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("2".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg)).unwrap();
                }
                 SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("2".to_string(), msg.clone())).unwrap();
                }
                _ => {}
            }
        }

         // Handle messages from party 3  <-- Added entire block for party 3
        if let Ok(recv_message_str) = rx31.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {  // Self-messaging
                            tx32.send(("3".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx42.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg)).unwrap(); // Send to self
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("3".to_string(), msg.clone())).unwrap();
                }
                _ => {}
            }
        }


        // Handle messages from party 4
        if let Ok(recv_message_str) = rx41.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("4".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("4".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() { // Added 3
                            tx32.send(("4".to_string(), value.clone())).unwrap();
                        }
                        if key == "4".to_string() {
                            tx42.send(("4".to_string(), value)).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) => {
                    tx12.send(("4".to_string(), msg.clone())).unwrap();
                    tx22.send(("4".to_string(), msg.clone())).unwrap();
                    tx32.send(("4".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("4".to_string(), msg)).unwrap();
                }
                SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("4".to_string(), msg.clone())).unwrap();
                    tx22.send(("4".to_string(), msg.clone())).unwrap();
                    tx32.send(("4".to_string(), msg.clone())).unwrap(); // Added 3
                    tx42.send(("4".to_string(), msg)).unwrap();
                }
                _ => {}
            }
        } else { // Exit if ANY receiver closes
            break;
        }
    });
    t
}


// Helper function for keygen routing
fn generate_router_keygen(
    rx11: crossbeam::channel::Receiver<Vec<u8>>,
    tx12: crossbeam::channel::Sender<(String, Vec<u8>)>,
    rx21: crossbeam::channel::Receiver<Vec<u8>>,
    tx22: crossbeam::channel::Sender<(String, Vec<u8>)>,
    rx31: crossbeam::channel::Receiver<Vec<u8>>,
    tx32: crossbeam::channel::Sender<(String, Vec<u8>)>,
) -> thread::JoinHandle<()> {
    let t =     thread::spawn(move || loop {
        //Party 1
        if let Ok(recv_message_str) = rx11.recv() {
            let recv_message: SendingMessages = bincode::deserialize(&recv_message_str).unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("1".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("1".to_string(), value.clone())).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) | SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("1".to_string(), msg.clone())).unwrap();
                    tx22.send(("1".to_string(), msg.clone())).unwrap();
                    tx32.send(("1".to_string(), msg.clone())).unwrap();
                }
                _ => {}
            }
        }

        //Party 2
        if let Ok(recv_message_str) = rx21.recv() {
            let recv_message: SendingMessages = bincode::deserialize(&recv_message_str).unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("2".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("2".to_string(), value.clone())).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) | SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("2".to_string(), msg.clone())).unwrap();
                    tx22.send(("2".to_string(), msg.clone())).unwrap();
                    tx32.send(("2".to_string(), msg.clone())).unwrap();
                }
                _ => {}
            }
        }

        // Party 3
        if let Ok(recv_message_str) = rx31.recv() {
            let recv_message = bincode::deserialize(&recv_message_str)
                .map_err(|why| format_err!("bincode deserialize error: {}", why))
                .unwrap();
            match recv_message {
                SendingMessages::P2pMessage(msg) => {
                    for (key, value) in msg {
                        if key == "1".to_string() {
                            tx12.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "2".to_string() {
                            tx22.send(("3".to_string(), value.clone())).unwrap();
                        }
                        if key == "3".to_string() {
                            tx32.send(("3".to_string(), value.clone())).unwrap();
                        }
                    }
                }
                SendingMessages::BroadcastMessage(msg) | SendingMessages::SubsetMessage(msg) => {
                    tx12.send(("3".to_string(), msg.clone())).unwrap();
                    tx22.send(("3".to_string(), msg.clone())).unwrap();
                    tx32.send(("3".to_string(), msg.clone())).unwrap();
                }
                _ => {}
            }
        } else { // Important: exit the loop when one channel closes
            break;
        }
    });
    t
}


#[test]
fn test_reshare_key_phase_create_refresh() {
    // Simulate a KeyGenPhase to get valid keys.
    let params = Parameters {
        threshold: 1,
        share_count: 3,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

    // Router for keygen
    let router = generate_router_keygen(rx11, tx12, rx21, tx22, rx31, tx32);

    let _party_ids = party_ids;
    let _params = params;
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t1 = thread::spawn(
        move || dmz_multi_keygen_local("1".to_string(), params, Some(party_ids), tx11, rx12)
    );
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t2 = thread::spawn(
        move || dmz_multi_keygen_local("2".to_string(), params, Some(party_ids), tx21, rx22)
    );
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t3 = thread::spawn(
        move || dmz_multi_keygen_local("3".to_string(), params, Some(party_ids), tx31, rx32)
    );


    router.join().unwrap();
    let keygen_result_1 = t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();

    // Refresh shares, keeping the same participants.
    let reshare_key_phase = ReshareKeyPhase::new(
        "1".to_string(),
        vec!["1".to_string(), "2".to_string(), "3".to_string()],
        vec!["1".to_string(), "2".to_string(), "3".to_string()],
        2, // Could be a different threshold.
        Some(keygen_result_1),
    );
    assert!(reshare_key_phase.is_ok());
}

#[test]
fn test_reshare_key_phase_create_do_refresh() {
    // Simulate a KeyGenPhase to get valid keys.
    let params = Parameters {
        threshold: 1,
        share_count: 3,
    };
    let party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

    // Router for keygen
    let router = generate_router_keygen(rx11, tx12, rx21, tx22, rx31, tx32);

    let _party_ids = party_ids;
    let _params = params;
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t1 = thread::spawn(
        move || dmz_multi_keygen_local("1".to_string(), params, Some(party_ids), tx11, rx12)
    );
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t2 = thread::spawn(
        move || dmz_multi_keygen_local("2".to_string(), params, Some(party_ids), tx21, rx22)
    );
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t3 = thread::spawn(
        move || dmz_multi_keygen_local("3".to_string(), params, Some(party_ids), tx31, rx32)
    );


    router.join().unwrap();
    let keys1 = t1.join().unwrap();
    let keys2 = t2.join().unwrap();
    let keys3 = t3.join().unwrap();
    let (tx11, rx11) = unbounded::<Vec<u8>>();
    let (tx12, rx12) = unbounded::<(String, Vec<u8>)>();
    let (tx21, rx21) = unbounded::<Vec<u8>>();
    let (tx22, rx22) = unbounded::<(String, Vec<u8>)>();
    let (tx31, rx31) = unbounded::<Vec<u8>>();
    let (tx32, rx32) = unbounded::<(String, Vec<u8>)>();

    // Router for keygen
    let router = generate_router_keygen(rx11, tx12, rx21, tx22, rx31, tx32);

    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t1 = thread::spawn(
        move || dmz_multi_reshare_local("1".to_string(), party_ids.clone(), party_ids, params.threshold, tx11, rx12, Some(keys1))
    );
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t2 = thread::spawn(
        move || dmz_multi_reshare_local("2".to_string(), party_ids.clone(), party_ids, params.threshold, tx21, rx22, Some(keys2))
    );
    let party_ids = _party_ids.clone();
    let params = _params.clone();
    let t3 = thread::spawn(
        move || dmz_multi_reshare_local("3".to_string(), party_ids.clone(), party_ids, params.threshold, tx31, rx32, Some(keys3))
    );


    router.join().unwrap();
    let reshare1 = t1.join().unwrap();
    let reshare2 = t2.join().unwrap();
    let reshare3 = t3.join().unwrap();

}

/// New integration test: keygen 5 parties (1..5), reshare to parties (1,3,5) with same threshold logic,
/// then perform offline + online signing over that new subset to ensure the signing path works after reshare.
#[test]
fn test_keygen_reshare_sign_subset_1_3_5_6_7() {
    // 1. Original keygen with parties 1..5
    let n: usize = 5;
    let params = Parameters {
        threshold: 3, // pick threshold 3 for 5 parties
        share_count: n,
    };
    let party_ids: Vec<String> = (1..=n).map(|i| i.to_string()).collect();

    let sender_receiver_map = generate_sender_receiver_map(party_ids.clone());
    let router = generate_multi_router(sender_receiver_map.clone());

    let mut keygen_threads = BTreeMap::new();
    for pid in &party_ids {
        let tx = sender_receiver_map[pid].1 .0.clone();
        let rx = sender_receiver_map[pid].0 .1.clone();
        let params_c = params.clone();
        let parties_c = party_ids.clone();
        let id = pid.clone();
        let handle = thread::spawn(move || dmz_multi_keygen_local(id, params_c, Some(parties_c), tx, rx));
        keygen_threads.insert(pid.clone(), handle);
    }
    let keygen_results: BTreeMap<String, String> = keygen_threads
        .into_iter()
        .map(|(id, h)| (id, h.join().unwrap()))
        .collect();
    drop(router); // original router thread exits once channels drop

    // 2. Reshare to subset 1,2,3,5, 6 (five parties). Keep threshold = 4 (now 4-of-5 required)
    let new_party_ids = vec!["1".to_string(), "2".to_string(), "3".to_string(), "5".to_string(), "6".to_string()];
    let new_threshold = 3;

    let sender_receiver_map_reshare = generate_sender_receiver_map(new_party_ids.clone());
    let router_reshare = generate_multi_router(sender_receiver_map_reshare.clone());

    let mut reshare_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_reshare[pid].1 .0.clone();
        let rx = sender_receiver_map_reshare[pid].0 .1.clone();
        let old_parties = party_ids.clone();
        let new_parties = new_party_ids.clone();
        let key_opt = keygen_results.get(pid).cloned(); // Some for existing, None for removed -> but all in new subset existed
        let id = pid.clone();
        let handle = thread::spawn(move || {
            dmz_multi_reshare_local(
                id,
                old_parties,
                new_parties,
                new_threshold,
                tx,
                rx,
                key_opt,
            )
        });
        reshare_threads.insert(pid.clone(), handle);
    }
    let reshare_results: BTreeMap<String, String> = reshare_threads
        .into_iter()
        .map(|(id, h)| (id, h.join().unwrap()))
        .collect();
    drop(router_reshare);

    // 3. Offline sign for subset 1,3,5
    let sign_params = Parameters {
        threshold: new_threshold,
        share_count: new_party_ids.len(),
    };
    let subset = new_party_ids.clone();
    let message = b"deadbeefcafebabefeedface01234567".to_vec();

    let sender_receiver_map_offline = generate_sender_receiver_map(new_party_ids.clone());
    let router_offline = generate_multi_router(sender_receiver_map_offline.clone());
    let mut offline_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_offline[pid].1 .0.clone();
        let rx = sender_receiver_map_offline[pid].0 .1.clone();
        let params_c = sign_params.clone();
        let subset_c = subset.clone();
        let keys_string = reshare_results.get(pid).unwrap().clone();
        let id = pid.clone();
        let handle = thread::spawn(move || {
            dmz_multi_offline_sign_local(id, params_c, subset_c, tx, rx, keys_string)
        });
        offline_threads.insert(pid.clone(), handle);
    }
    let offline_results: BTreeMap<String, String> = offline_threads
        .into_iter()
        .map(|(id, h)| (id, h.join().unwrap()))
        .collect();
    drop(router_offline);

    // 4. Online sign for subset 1,3,5
    let sender_receiver_map_online = generate_sender_receiver_map(new_party_ids.clone());
    let router_online = generate_multi_router(sender_receiver_map_online.clone());
    let mut online_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_online[pid].1 .0.clone();
        let rx = sender_receiver_map_online[pid].0 .1.clone();
        let offline_result = offline_results.get(pid).unwrap().clone();
        let msg = message.clone();
        let handle = thread::spawn(move || dmz_multi_online_sign_local(tx, rx, offline_result, msg));
        online_threads.insert(pid.clone(), handle);
    }
    let _signatures: BTreeMap<String, String> = online_threads
        .into_iter()
        .map(|(id, h)| (id, h.join().unwrap()))
        .collect();
    drop(router_online);

    let party_ids = new_party_ids.clone();

    // 5. Now reshare the result of the reshare and this time we have participants left 1,3,5,6 and threshold 3
    let party_ids = new_party_ids;
    let new_party_ids = vec!["1".to_string(),"5".to_string(), "6".to_string(), "7".to_string()];

    let new_threshold = 3; // only 3 required now (3-of-4)


    let sender_receiver_map_reshare = generate_sender_receiver_map(new_party_ids.clone());
    let router_reshare = generate_multi_router(sender_receiver_map_reshare.clone());
    let mut reshare_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_reshare[pid].1 .0.clone();
        let rx = sender_receiver_map_reshare[pid].0 .1.clone();
        let old_parties = party_ids.clone();
        let new_parties = new_party_ids.clone();
        let key_opt = reshare_results.get(pid).cloned();
        let id = pid.clone();
        let handle = thread::spawn(move || dmz_multi_reshare_local(id, old_parties, new_parties, new_threshold, tx, rx, key_opt));
        reshare_threads.insert(pid.clone(), handle);
    }
    let reshare_results: BTreeMap<String, String> = reshare_threads.into_iter().map(|(id,h)|(id,h.join().unwrap())).collect();
    drop(router_reshare);

    // Offline with the reshared keys

    let sign_params = Parameters {
        threshold: new_threshold,
        share_count: new_party_ids.len(),
    };
    let subset = new_party_ids.clone();

    let sender_receiver_map_offline = generate_sender_receiver_map(new_party_ids.clone());
    let router_offline = generate_multi_router(sender_receiver_map_offline.clone());
    let mut offline_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_offline[pid].1 .0.clone();
        let rx = sender_receiver_map_offline[pid].0 .1.clone();
        let params_c = sign_params.clone();
        let subset_c = subset.clone();
        let keys_string = reshare_results.get(pid).unwrap().clone();
        let id = pid.clone();
        let handle = thread::spawn(move || {
            dmz_multi_offline_sign_local(id, params_c, subset_c, tx, rx, keys_string)
        });
        offline_threads.insert(pid.clone(), handle);
    }
    let offline_results: BTreeMap<String, String> = offline_threads
        .into_iter()
        .map(|(id, h)| (id, h.join().unwrap()))
        .collect();
    drop(router_offline);

    // Sign online
    let sender_receiver_map_sign = generate_sender_receiver_map(new_party_ids.clone());
    let router_sign = generate_multi_router(sender_receiver_map_sign.clone());
    let mut sign_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_sign[pid].1 .0.clone();
        let rx = sender_receiver_map_sign[pid].0 .1.clone();
        let offline_result = offline_results.get(pid).unwrap().clone();
        let msg = message.clone();
        let handle = thread::spawn(move || dmz_multi_online_sign_local(tx, rx, offline_result, msg));
        sign_threads.insert(pid.clone(), handle);
    }
    let signatures: BTreeMap<String, String> = sign_threads
        .into_iter()
        .map(|(id, h)| (id, h.join().unwrap()))
        .collect();
    drop(router_sign);

    /// Verify all signatures are identical
    let first_signature = signatures.values().next().unwrap();
    for sig in signatures.values() {
        assert_eq!(sig, first_signature);
    }
    // check that there are exactly four signatures
    assert_eq!(signatures.len(), 4);

}

#[test]
fn test_keygen_reshare_sign_subset_1_3_5_threshold3() {
    // Original 5 parties, threshold 3
    let n: usize = 5;
    let params = Parameters {
        threshold: 3,
        share_count: n,
    };
    let party_ids: Vec<String> = (1..=n).map(|i| i.to_string()).collect();

    let sender_receiver_map = generate_sender_receiver_map(party_ids.clone());
    let router = generate_multi_router(sender_receiver_map.clone());
    let mut keygen_threads = BTreeMap::new();
    for pid in &party_ids {
        let tx = sender_receiver_map[pid].1 .0.clone();
        let rx = sender_receiver_map[pid].0 .1.clone();
        let params_c = params.clone();
        let parties_c = party_ids.clone();
        let id = pid.clone();
        let handle = thread::spawn(move || dmz_multi_keygen_local(id, params_c, Some(parties_c), tx, rx));
        keygen_threads.insert(pid.clone(), handle);
    }
    let keygen_results: BTreeMap<String, String> = keygen_threads.into_iter().map(|(id,h)|(id,h.join().unwrap())).collect();
    drop(router);

    // Reshare to 1,3,5 with threshold 3
    let new_party_ids = vec!["1".to_string(), "3".to_string(), "5".to_string()];
    let new_threshold = 3; // all must participate
    let sender_receiver_map_reshare = generate_sender_receiver_map(new_party_ids.clone());
    let router_reshare = generate_multi_router(sender_receiver_map_reshare.clone());
    let mut reshare_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_reshare[pid].1 .0.clone();
        let rx = sender_receiver_map_reshare[pid].0 .1.clone();
        let old_parties = party_ids.clone();
        let new_parties = new_party_ids.clone();
        let key_opt = keygen_results.get(pid).cloned();
        let id = pid.clone();
        let handle = thread::spawn(move || dmz_multi_reshare_local(id, old_parties, new_parties, new_threshold, tx, rx, key_opt));
        reshare_threads.insert(pid.clone(), handle);
    }
    let reshare_results: BTreeMap<String, String> = reshare_threads.into_iter().map(|(id,h)|(id,h.join().unwrap())).collect();
    drop(router_reshare);

    // Offline sign
    let sign_params = Parameters { threshold: new_threshold, share_count: new_party_ids.len() };
    let subset = new_party_ids.clone();
    let message = b"feedfacecafedeadbeef000011112222".to_vec();
    let sender_receiver_map_offline = generate_sender_receiver_map(new_party_ids.clone());
    let router_offline = generate_multi_router(sender_receiver_map_offline.clone());
    let mut offline_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_offline[pid].1 .0.clone();
        let rx = sender_receiver_map_offline[pid].0 .1.clone();
        let params_c = sign_params.clone();
        let subset_c = subset.clone();
        let keys_string = reshare_results.get(pid).unwrap().clone();
        let id = pid.clone();
        let handle = thread::spawn(move || dmz_multi_offline_sign_local(id, params_c, subset_c, tx, rx, keys_string));
        offline_threads.insert(pid.clone(), handle);
    }
    let offline_results: BTreeMap<String, String> = offline_threads.into_iter().map(|(id,h)|(id,h.join().unwrap())).collect();
    drop(router_offline);

    // Online sign
    let sender_receiver_map_online = generate_sender_receiver_map(new_party_ids.clone());
    let router_online = generate_multi_router(sender_receiver_map_online.clone());
    let mut online_threads = BTreeMap::new();
    for pid in &new_party_ids {
        let tx = sender_receiver_map_online[pid].1 .0.clone();
        let rx = sender_receiver_map_online[pid].0 .1.clone();
        let offline_result = offline_results.get(pid).unwrap().clone();
        let msg = message.clone();
        let handle = thread::spawn(move || dmz_multi_online_sign_local(tx, rx, offline_result, msg));
        online_threads.insert(pid.clone(), handle);
    }
    let _signatures: BTreeMap<String, String> = online_threads.into_iter().map(|(id,h)|(id,h.join().unwrap())).collect();
    drop(router_online);
}