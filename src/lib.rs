use elliptic_curve::rand_core::{OsRng, RngCore};
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use hex;

pub struct Wallet {
    pub sk : SecretKey,
    pub pk : String,
    pub address: String,
}

pub struct RPC {
    pub url: String,
}

impl Wallet {
    pub fn new(sk : Option<String>) -> Wallet {
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
        let pk = PublicKey::from_secret_key(&secp,&sk);
        return pk;
    }

    pub fn generate_address(pubkey : PublicKey) -> String {
        let sha = Sha256::digest(&pubkey.serialize());
        let addr_raw = Ripemd160::digest(&sha);
        let mut hasher_checksum = Sha256::new();
        hasher_checksum.update(&addr_raw);
        let checksum = &hasher_checksum.finalize()[..4];
        let addr = [&addr_raw[..], checksum].concat();
        return hex::encode(addr);
    }






}

impl RPC {
    pub fn new(url: String) -> RPC {
        RPC {
            url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet() {
        let wallet = Wallet::new(None);
        print!("Secret Key: {:?}\n", SecretKey::clone(&wallet.sk).display_secret() );
        print!("Public Key: {:?}\n", wallet.pk);
        print!("Address: {:?}\n", wallet.address);
    }



}
