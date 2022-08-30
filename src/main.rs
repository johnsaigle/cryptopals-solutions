use std::io;
use std::fs;
use hex::decode;
use base64::{encode};
use std::ops::BitXor;
use anyhow::{Result,Error};
use std::collections::HashMap;
use std::collections::BTreeMap;

fn hex_to_base64(buffer: String) -> Result<String, anyhow::Error> {
    let hex = hex::decode(buffer)?;
    Ok(base64::encode(hex))
}

fn challenge2() -> Result<Vec<u8>, anyhow::Error> {
    let v1 = hex::decode("1c0111001f010100061a024b53535009181c")?;
    let v2 = hex::decode("686974207468652062756c6c277320657965")?;
    let v3: Vec<u8> = v1
        .iter()
        .zip(v2.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    Ok(v3)
}

fn challenge3() -> Result<u8, anyhow::Error> {
    let cipher = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
    // change this to loop 0-255
    const alphabet: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    // score
    // compare frequencies of letters in decryption to known frequency of english characters
    // build dict from sample
    // store it in a vector
    // do euclidean distance between vectors; find smallest
    let contents = fs::read_to_string("sample-lower.txt")
        .expect("Should have been able to read the file");

    let mut letters = HashMap::new();

    for ch in contents.chars().filter(|x| x.is_alphabetic() && x.is_ascii()) {
        letters.entry(ch).and_modify(|counter| *counter += 1).or_insert(1);
    }
    let count_b: BTreeMap<&u32,&char> = letters.iter().map(|(k,v)| (v,k)).collect();
    println!("{:?}", count_b);
    //score -- do Euclidean distance on the vectors
    Ok(1)
}

fn main() -> Result<()> {
    let mut buffer = String::new();
    let stdin = io::stdin(); // We get `Stdin` here.
    //stdin.read_line(&mut buffer)?;

    // Hex to base64
    //let res = hex_to_base64(buffer)?;
    
    //
    let res = challenge2()?;
    println!("{:?}", res);
    println!("{:?}", hex::encode(res));
    challenge3();
    Ok(())
}
