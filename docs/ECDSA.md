
- [Elliptic Curve Digital Signature Algorithm(ECDSA)](#elliptic-curve-digital-signature-algorithmecdsa)
- [Operations](#operations)
  - [KeyGen](#keygen)
  - [Sign(Offline)](#signoffline)
  - [Sign(Online)](#signonline)
- [Messaging](#messaging)


## Elliptic Curve Digital Signature Algorithm(ECDSA)


- For a t-n threshold schema. $t>0, n>t$.
- Currently using secp256k1 curve.

## Operations

In this section, we introduce the input and output of the operations and some things to keep in mind.

### KeyGen


**Input:**

```rust
impl KeyGenPhase {
    /// partyid: The party id(index). Hex-string. (0, the modulus of the curve)
    /// params: t,n. t>0, n>t.
    /// party_ids: The list of parties whose size is equal to params.n.
    pub fn new(
        partyid: String,
        params: Parameters,
        party_ids: &Option<Vec<String>>,
    ) -> Result<Self, anyhow::Error>;
}
```

- the modulus of secp256k1 curve is `fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`.
- There is no requirement for the order of `ids` in the `party_ids`.
- The `Parameters` is defined as follows:

```rust
pub struct Parameters {
    pub threshold: usize,   // t
    pub share_count: usize, // n
}
```


**Output:**

Each party owns $key_i = (sk_i, pk_i)$. The structure of the $key_i$ is as follows:
  
```
{
  // i
  "index": ...,
  "participants": ...,
  // pk_i
  "pubkey": {
    "pk": ... ,
    "share_pks": ... 
  },
  // sk_i
  "privkey": ...
}
```

Here is a sample:

```json
{
  "index": "1",
  "participants": [
    "1",
    "2",
    "3"
  ],
  "pubkey": {
    "pk": [
      "10ec64d0a73c134c53ed764e86743397bab3bb06bdbbd638321b87eda9c6614e",
      "6b7df1b8b41c41fc69fef0d87fc8ee9d01c021936d3b44cd62883894cd60de14"
    ],
    "share_pks": {
      "1": [
        "7a39ace81396d9c65dfb8f4c8ebdf3d5850447e129edbac052558b483b01ba52",
        "d942c292f40e65715f722b1db87d0ceaa122f9d6457eacffbd021653b0a6f65"
      ],
      "2": [
        "6b31a24d2705971d18fffbdc2edbf4e97d01c2b4aea75df2a01566f03c269804",
        "5f94b59a0a97d604e356ca21c27b64c0f5dfc4e8315e4be8179c5292a8b6d015"
      ],
      "3": [
        "79a7c9632cbfd98f890d9d4670ac301fda42db178b9b8ec2a2860e44488130da",
        "af7d69f73529d8235ae6dc9f896bd81830777ff9667d9ab1fc5b37599c712378"
      ]
    }
  },
  "privkey": {
    "cl_sk": "1b557b69c49c0715403f618907a051c012adc57e9ea6b17aa912d68b6056b1d24b5c10a36269ac0367fb4c17c3fc85825c77688e651bf7f585c25ff5011d83176f5add844e75e764a409c555ba01865f0718b133abe037aba34c7fa9cb6973d7652a00eaf24e1a623c00ebbd6abc6dc6b4e0662ebca1674b3ffe8009f63f47d888154aa02de7c1e96f6ec3927",
    "ec_sk": "a23ae304a46c36bbf52e1373daa4446dda3f3b1b721a77c84a2ec86f54e6970c",
    "share_sk": "f869bd11e46d036cdd81ad9940c9d510d24114bba12edfa626a966677058ff5a"
  }
}
```



### Sign(Offline)


**Input:**

```rust
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
    ) -> Result<Self, anyhow::Error>;
}
```


**Output:**

```json
{"data": ...}
```

- This is only an intermediate output.


### Sign(Online)


**Input:**


```rust
impl SignPhaseOnline {
    /// offline_result: The output of SignOffline.
    /// message_bytes: The hash value of the message to be signed, 32 bytes.
    pub fn new(offline_result: &String, message_bytes: Vec<u8>) -> Result<Self, anyhow::Error>;
}
```
- The message to be signed needs to be hashed first by the caller itself.

**Output:**

All participating signers will receive a signature.


Here is a sample:

```json
{
  "s": "14af6f72d8bd26faccd75ff092544d15a3dce5d97e897773b515cd70ab0453e7",
  "r": "3687024517eb44de2cfaa6166866c9bd2587090317a4d12521b571c7509319b4",
  "recid": 0
}
```

- `recid` is the recovery id.



## Messaging


All **Phases** have implemented the `process_begin` and `msg_handler`. Please refer to **Step 2** and **Step 3** of [README](../README.md#usage) for how to these.


```rust
pub fn process_begin(&mut self) -> Result<SendingMessages, anyhow::Error>;
pub fn msg_handler(
    &mut self,
    index: String,
    recv_msg: &Vec<u8>,
) -> Result<SendingMessages, anyhow::Error>;
```

The `SendingMessages` returned by `process_begin` and `msg_handler`.

```rust
pub enum SendingMessages {
    NormalMessage(String, Vec<u8>),       // (to, message)
    P2pMessage(HashMap<String, Vec<u8>>), // (to, message)
    SubsetMessage(Vec<u8>),               // (message), send according to subset
    BroadcastMessage(Vec<u8>),            // (message), send to all participants
    EmptyMsg,
    KeyGenSuccessWithResult(String),
    SignOfflineSuccessWithResult(String),
    SignOnlineSuccessWithResult(String),
}
```



