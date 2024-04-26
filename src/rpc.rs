use serde::{Deserialize, Serialize};

use ripemd::Digest as RipemdDigest;

pub struct RPC {
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Model {
    code: i32,
    pub(crate) data: Data,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
pub struct Data {
    difficulty: f64,
    hash: String,
    height: i64,
    is_janushash: bool,
    pub(crate) pinHash: String,
    pub(crate) pinHeight: i32,
    synced: bool,
    worksum: f64,
    worksumHex: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Transaction {
    pub(crate) pinHeight: u32,
    pub(crate) nonceId: u32,
    pub(crate) toAddr: String,
    pub(crate) amountE8: u64,
    pub(crate) feeE8: u64,
    pub(crate) signature65: String,
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

    pub fn send_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&format!("{}/transaction/add", self.url))
            .json(&transaction)
            .send()?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to send transaction",
            )))
        }
    }
}
