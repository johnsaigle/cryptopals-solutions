// Using unit tests which mean functions are never called in a normal way
#![allow(dead_code)]
#![allow(clippy::needless_return)]
use ::core::iter::zip;
use bitvec::prelude::*;
use core::panic;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};

use anyhow::Ok;
use bitvec::view::BitView;
// use anyhow::Error;

fn hex_to_base64(input: &str) -> String {
    base64::encode(hex::decode(input).unwrap())
}

fn xor(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    let result: Vec<u8> = zip(left, right).map(|(l, r)| l ^ r).collect();

    return result;
}

fn brute_force_single_byte_xor(ciphertext: Vec<u8>) -> (Vec<u8>, u32) {
    const PENALTY_CHARACTER_FREQUENCY: u32 = 1;
    const PENALTY_NEITHER_ALPHABETIC_NOR_WHITESPACE: u32 = 5;

    // Distance is bad. Small distance means similar to English language
    let mut smallest_distance = u32::MAX;
    let mut likely_plaintext = vec![];

    // Frequency distribution of letters in English
    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    let etaoin: &str = "etaoinshrdlcumwfgypbvkjxqz";

    // Loop over all possible keys (single bytes)
    for byte in 0..u8::MAX {
        // XOR a vector of ciphertext.len() `byte`s against the ciphertext
        // e.g. a key of 'A' is a Vector: [A, A, A, ... ]
        let plaintext = xor(ciphertext.clone(), vec![byte; ciphertext.len()]);

        // Invariant
        if plaintext.len() != ciphertext.len() {
            panic!("Plaintext length is different from ciphertext length");
        }

        let mut decrypted_character_frequency: BTreeMap<char, u32> = BTreeMap::new();
        for byte in &plaintext {
            // Ignore non ASCII. Not helpful for finding English text
            let chr = *byte as char;
            let count = decrypted_character_frequency.entry(chr).or_insert(0);
            *count += 1;
        }

        // Convert the BTreeMap into a Vector of sorted ordered pairs.
        // Sort the resulting pairs by comparing by the values of the BTreeMap.
        // The result is a vector of pairs where the X coordinate is the (decrypted) character and the y
        // coordinate is the frequency, sorted by the character (i.e. the character that appears
        // most frequently is the X-coordinate of first element of the vector).
        let mut character_frequency_coordinates = Vec::from_iter(decrypted_character_frequency);
        character_frequency_coordinates
            .sort_by(|&(_, frequency_a), &(_, frequency_b)| frequency_b.cmp(&frequency_a));

        // Just for safety. Otherwise we might get a bogus score of 0 at the end of the for loop
        // calculations.
        if character_frequency_coordinates.is_empty() {
            continue;
        }

        // A higher distance is bad. Lower distance means that it's close to an English sentence
        let mut vector_distance = 0;

        // Iterate over the vector of sorted pairs.
        // Compare the X value of the pair with the character ETAOIN string
        // Increase Hamming distance count when the X values from the vector diverge from
        // the ETAOIN string.
        // let mut etaoin_iter = etaoin.chars();
        for (i, char) in zip(0..etaoin.len(), etaoin.chars()) {
            if i >= character_frequency_coordinates.len() {
                break;
            }

            let plain_char = character_frequency_coordinates[i].0;
            // Hack: penalize heavily if not a normal english character
            if !plain_char.is_alphabetic() && !plain_char.is_ascii_whitespace() {
                // make match less likely if we get a non-printable character
                vector_distance += PENALTY_NEITHER_ALPHABETIC_NOR_WHITESPACE;
            }
            if !plain_char.eq_ignore_ascii_case(&char) {
                vector_distance += PENALTY_CHARACTER_FREQUENCY;
                continue;
            }
            // println!("No distance increase: Match on plain {plain_char} and {char}");
        }

        if vector_distance < smallest_distance {
            // println!(
            //     "Replacing prev smallest distance {} with new distance {}",
            //     smallest_distance, vector_distance
            // );
            // println!("Distribution {:?}", v);
            smallest_distance = vector_distance;
            likely_plaintext = plaintext;
        }
    }
    return (likely_plaintext, smallest_distance);
}

/// Iterate over a file containing ciphertext and find which one is encrypted.
fn detect_single_byte_xor() -> Result<(Vec<u8>, u32), anyhow::Error> {
    let mut plaintext = vec![];
    let mut smallest_distance = u32::MAX;

    let file = File::open("data/set1chall4.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let cipher_bytes =
            hex::decode(line.unwrap()).expect("Ciphertext line should be hex-decodable");
        let (this_plaintext, this_distance) = brute_force_single_byte_xor(cipher_bytes);

        if this_distance < smallest_distance {
            smallest_distance = this_distance;
            plaintext = this_plaintext;
        }
    }

    if plaintext.is_empty() {
        return Err(anyhow::format_err!("Plaintext was never inititalized"));
    }

    Ok((plaintext, smallest_distance))
}

fn encrypt_repeating_key_xor(plaintext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    // let key = "ICE".as_bytes();
    // Do division: q = mn + r.
    let quotient = plaintext.len() / key.len();
    let remainder = plaintext.len() % key.len();
    let mut key_vector: Vec<u8> = key.repeat(quotient);
    key_vector.extend_from_slice(&key[0..remainder]);

    xor(plaintext, key_vector)
}

fn hamming_distance(left: Vec<u8>, right: Vec<u8>) -> u32 {
    if left.len() != right.len() {
        panic!("Vectors are of different length");
    }
    let mut distance = 0;
    for (left_byte, right_byte) in zip(left, right) {
        // Compare each byte at the level of individual bits
        let left_bit_slice = left_byte.view_bits::<Lsb0>();
        let right_bit_slice = right_byte.view_bits::<Lsb0>();

        // Sanity check for length: Must always be equal to 8. Both slices must have the same length.
        let bit_slice_length = left_bit_slice.len();
        if bit_slice_length != right_bit_slice.len() {
            panic!("Bit vectors are of different length");
        }
        for i in 0..bit_slice_length {
            if left_bit_slice.get(i) != right_bit_slice.get(i) {
                distance += 1;
            }
        }
    }
    distance
}

fn main() {}

#[test]
fn test_set1_challenge1() {
    let c1_input: String = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string();
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        hex_to_base64(&c1_input)
    );
}

#[test]
fn test_set1_challenge2() {
    let slice_a: String = "1c0111001f010100061a024b53535009181c".to_string();
    let slice_b: String = "686974207468652062756c6c277320657965".to_string();
    assert_eq!(
        "746865206b696420646f6e277420706c6179".to_string(),
        hex::encode(xor(
            hex::decode(slice_a).unwrap(),
            hex::decode(slice_b).unwrap()
        ))
    );
}

#[test]
fn test_set1_challenge3() {
    let input: String =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
    let (plaintext_bytes, _) = brute_force_single_byte_xor(hex::decode(input).unwrap().to_vec());
    let plaintext_string =
        String::from_utf8(plaintext_bytes).expect("plaintext should be printable");
    // This string isn't found on the challenge page but it's correct.
    // Ensure that the function spits this out.
    assert_eq!(
        "Cooking MC's like a pound of bacon".to_string(),
        plaintext_string
    );
}

#[test]
fn test_set1_challenge4() {
    let (plaintext_bytes, _) = detect_single_byte_xor().unwrap();
    let plaintext_string =
        String::from_utf8(plaintext_bytes).expect("plaintext should be printable");
    assert_eq!(
        "Now that the party is jumping\n".to_string(),
        plaintext_string
    );
}

#[test]
fn test_set1_challenge5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        .as_bytes()
        .to_vec();
    let key = "ICE".as_bytes().to_vec();

    let ciphertext = encrypt_repeating_key_xor(plaintext, key);
    let ciphertext_hexstring = hex::encode(ciphertext);

    assert_eq!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        ciphertext_hexstring
    );
}

#[test]
fn test_hamming_distance() {
    let left = "this is a test".as_bytes().to_vec();
    let right = "wokka wokka!!!".as_bytes().to_vec();
    assert_eq!(37u32, hamming_distance(left, right));
}
