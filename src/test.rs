#[cfg(test)]
pub mod tests {
    use crate::rpc::{Transaction, RPC};
    use crate::wallet::Wallet;
    use secp256k1::SecretKey;

    #[test]
    fn test_wallet() {
        let wallet = Wallet::new(None);
        print!(
            "Secret Key: {:?}\n",
            SecretKey::clone(&wallet.sk).display_secret()
        );
        print!("Public Key: {:?}\n", wallet.pk);
        print!("Address: {:?}\n", wallet.address);
    }

    #[test]
    fn test_wallet_with_sk() {
        let wallet = Wallet::new(Some(
            "dcf9b59a067663f2afacd80eec49af2e8f2aea09507b7f294e25638f35028cf5".to_string(),
        ));
        println!("{:?}", wallet.address)
    }

    #[test]
    fn test_rpc() {
        let rpc = RPC {
            url: "http://51.75.21.134:3001".to_string(),
        };
        let result = rpc.get_chain_head();
        print!("{:?}", result);
    }

    #[test]
    fn test_send() {
        let rpc = RPC {
            url: "http://51.75.21.134:3100".to_string(),
        };
        let data = rpc.get_chain_head().unwrap();
        let pin_height = &data.data.pinHeight;
        let wallet = Wallet::new(Some(
            "dcf9b59a067663f2afacd80eec49af2e8f2aea09507b7f294e25638f35028cf5".to_string(),
        ));
        let nonce_id: i32 = 0;
        let to = "0000000000000000000000000000000000000000de47c9b2".to_string();
        let amount_e8 = 100000000;
        let fee_e8 = 9992;

        let sig = wallet.sign_tx(data.clone(), to.clone(), amount_e8, nonce_id as u32, fee_e8);

        println!("Signature : {:?}", sig);

        let tx = Transaction {
            pinHeight: *pin_height as u32,
            nonceId: nonce_id as u32,
            toAddr: to,
            amountE8: amount_e8,
            feeE8: fee_e8,
            signature65: sig,
        };

        let result = rpc.send_transaction(tx);

        print!("{:?}", result);
    }
}
