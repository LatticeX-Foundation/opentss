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
use crate::protocols::multi_party::dmz21::keygen::KeyGenPhase;
use crate::protocols::multi_party::dmz21::keygen::Parameters;
use crate::protocols::multi_party::dmz21::sign::SignPhase;
use crate::protocols::multi_party::dmz21::sign::SignPhaseOnline;
use anyhow::format_err;
use crossbeam_channel::*;
use std::thread;

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
        println!("key1 = {}", key);
    });
    let params2 = params.clone();
    let party_ids2 = party_ids.clone();
    let t2 = thread::spawn(move || {
        let key = dmz_multi_keygen_local("2".to_string(), params2, party_ids2, tx21, rx22);
        println!("key2 = {}", key);
    });
    let params3 = params.clone();
    let party_ids3 = party_ids.clone();
    let t3 = thread::spawn(move || {
        let key = dmz_multi_keygen_local("3".to_string(), params3, party_ids3, tx31, rx32);
        println!("key3 = {}", key);
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
        println!("offline succeed");
        let signature1 = dmz_multi_online_sign_local(tx11, rx12, offline_result1, message1);
        println!("signature1 = {}\n", signature1);
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
        println!("offline succeed");
        let siganture2 = dmz_multi_online_sign_local(tx21, rx22, offline_result2, message2);
        println!("signature2 = {}\n", siganture2);
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
        println!("offline succeed");
        let signature3 = dmz_multi_online_sign_local(tx31, rx32, offline_result3, message3);
        println!("signature3 = {}", signature3);
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
    println!("time = {:?}", time::now() - start);
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
    println!("time = {:?}", time::now() - start);
}
