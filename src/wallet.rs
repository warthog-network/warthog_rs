use crate::rpc::Model;
use digest::Digest;
use rand_core::{OsRng, RngCore};
use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;

pub struct Wallet {
    pub sk: SecretKey,
    pub pk: String,
    pub address: String,
}

impl Wallet {
    pub fn new(sk: Option<String>) -> Wallet {
        let secret_key = match sk {
            Some(sk) => SecretKey::from_slice(&hex::decode(sk).unwrap()).unwrap(),
            None => Self::generate_sk(),
        };
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

    pub fn sign_tx(
        &self,
        tx_data: Model,
        to: String,
        amount: u64,
        nonce_id: u32,
        fee_e8: u64,
    ) -> String {
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
        let sk = self.sk;

        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&*sha).expect("32 bytes");
        let sig = secp.sign_ecdsa_recoverable(&msg, &sk);

        let (rec_id_value, sig_serialized) = sig.serialize_compact();
        let rec_id = rec_id_value.to_i32();

        // Concatenate r, s and recovery id
        let mut signature65 = vec![];
        signature65.extend(&sig_serialized[..32]); // r
        signature65.extend(&sig_serialized[32..]); // s
        signature65.push(rec_id as u8); // recovery id

        hex::encode(signature65)
    }
}
