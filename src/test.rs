#[cfg(test)]
pub mod tests {
    use secp256k1::SecretKey;
    use crate::Wallet;


    #[test]
    fn test_wallet() {
        let wallet = Wallet::new(None);
        print!("Secret Key: {:?}\n", SecretKey::clone(&wallet.sk).display_secret());
        print!("Public Key: {:?}\n", wallet.pk);
        print!("Address: {:?}\n", wallet.address);
    }
}