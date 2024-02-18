// Using unit tests which mean functions are never called in a normal way
#![allow(dead_code)]

use::core::iter::zip;


fn hex_to_base64(input: &str) -> String {
    base64::encode(hex::decode(input).unwrap())
}

fn xor(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
     let result: Vec<u8> = 
        zip(left, right)
        .into_iter()
        .map(|(l, r)| l ^ r)
        .collect();

    return result;
}

fn freq_analysis(ciphertext: Vec<u8>) -> {
    // Create a normal distribution of characters in English
    // Take input string
    // XOR against a character (I guess try all 255 ASCII)
    // Count occurrences of all characters in the result
    // Compare character count against normal distribution
    // Use e.g. Hamming distance to score the similarity
    // The answer is the XOR character with the resulting frequency closest
    //  to the normal distribution
    
    // Loop over all possible keys
    for i in 0..u8::MAX {

    }

}

fn main() {

}


#[test]
fn test_set1_challenge1() {
    let c1_input: String = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();
    assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", hex_to_base64(&c1_input));
}

#[test]
fn test_set1_challenge2() {
    let slice_a: String = "1c0111001f010100061a024b53535009181c".to_string();
    let slice_b: String = "686974207468652062756c6c277320657965".to_string();
    assert_eq!(
        "746865206b696420646f6e277420706c6179".to_string(),
        hex::encode(
        xor(
        hex::decode(slice_a).unwrap(),
        hex::decode(slice_b).unwrap()
        ))
    );
}

#[test]
fn test_set1_challenge3() {
    let input: String = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
}
