use elliptic_curve::rand_core::{OsRng, RngCore};
use hex;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Sha256};
use serde::{Deserialize, Serialize};

pub struct Wallet {
    pub sk: SecretKey,
    pub pk: String,
    pub address: String,
}

pub struct RPC {
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[derive(Clone)]
pub struct Model {
    code: i32,
    data: Data,
}

#[derive(Serialize, Deserialize, Debug)]
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Data {
    difficulty: f64,
    hash: String,
    height: i64,
    is_janushash: bool,
    pinHash: String,
    pinHeight: i64,
    synced: bool,
    worksum: f64,
    worksumHex: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Transaction {
    pinHeight: u32,
    nonceId: u32,
    toAddr: String,
    amountE8: u64,
    feeE8: u64,
    signature65: String,
}

impl Wallet {
    pub fn new(sk: Option<String>) -> Wallet {
        let secret_key = sk.map_or(Self::generate_sk(), |k| k.parse().unwrap());
        let pubkey = Self::generate_pk(secret_key);
        Wallet {
            sk: secret_key,
            pk: pubkey.clone().to_string(),
            address: Self::generate_address(pubkey),
        }
    }

    pub fn generate_sk() -> SecretKey {
        let mut sk_bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut sk_bytes);
        return SecretKey::from_slice(&sk_bytes).unwrap();
    }

    pub fn generate_pk(sk: SecretKey) -> PublicKey {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        return pk;
    }

    pub fn generate_address(pubkey: PublicKey) -> String {
        let sha = Sha256::digest(&pubkey.serialize());
        let addr_raw = Ripemd160::digest(&sha);
        let mut hasher_checksum = Sha256::new();
        hasher_checksum.update(&addr_raw);
        let checksum = &hasher_checksum.finalize()[..4];
        let addr = [&addr_raw[..], checksum].concat();
        return hex::encode(addr);
    }

    pub fn sign_tx(&self, tx_data : Model, to: String, amount : u64, nonce_id: i32, fee_e8: u64) -> String {
        let pin_height = tx_data.data.pinHeight;
        let pin_hash = tx_data.data.pinHash;

        let mut to_sign: Vec<u8> = Vec::new();
        to_sign.extend(hex::decode(pin_hash).unwrap()); // decode hex string to bytes
        to_sign.extend(&pin_height.to_be_bytes());
        to_sign.extend(&nonce_id.to_be_bytes());
        // Fill with 3 bytes of 0
        to_sign.extend(&[0, 0, 0]);
        to_sign.extend(&fee_e8.to_be_bytes());
        // address that we delete 4 bytes of checksum
        let to_addr_bytes = hex::decode(to).unwrap();
        to_sign.extend(&to_addr_bytes[0..20]);
        to_sign.extend(&amount.to_be_bytes());



        let sha = Sha256::digest(to_sign);
        let wallet = Wallet::new(Some("dcf9b59a067663f2afacd80eec49af2e8f2aea09507b7f294e25638f35028cf5".to_string()));
        let sk = wallet.sk;

        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&sha).unwrap();
        // recoverable signature
        let sig = secp.sign_ecdsa_recoverable(&msg, &sk);

        let (recid, sig_bytes) = sig.serialize_compact();

        let mut full_sig: Vec<u8> = Vec::new();
        full_sig.extend_from_slice(&sig_bytes);
        full_sig.push(recid.to_i32() as u8);

        let signature = hex::encode(full_sig);

        return signature;


    }
}

impl RPC {
    pub fn new(url: String) -> RPC {
        RPC { url }
    }

    pub fn get_chain_head(&self) -> Result<Model, Box<dyn std::error::Error>> {
        let url = format!("{}/chain/head", self.url);
        let resp = reqwest::blocking::get(&url)?;
        let model: Model = serde_json::from_str(&resp.text()?)?;
        Ok(model)
    }

    pub fn send_transaction(&self, transaction: Transaction) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let res = client.post(&format!("{}/transaction/add", self.url))
            .json(&transaction)
            .send()?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to send transaction")))
        }
    }
}
#[cfg(test)]
mod test;
