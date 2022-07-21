use std::io;
use hex::decode;
use base64::{encode};
use anyhow::{Result,Error};

fn hex_to_base64(buffer: String) -> Result<String, anyhow::Error> {
    let hex = hex::decode(buffer)?;
    Ok(base64::encode(hex))
}

fn main() -> Result<()> {
    let mut buffer = String::new();
    let stdin = io::stdin(); // We get `Stdin` here.
    stdin.read_line(&mut buffer)?;
    let res = hex_to_base64(buffer)?;
    println!("{}", res);
    Ok(())
}
