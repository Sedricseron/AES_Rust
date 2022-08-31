use crate::aes::{decrypt_block, encrypt_block};
use std::convert::TryFrom;
use crate::appendix::{bytes_to_matrix, matrix_to_bytes, xor_arrays};

pub fn ecb_encrypt(mut message: Vec<u8>, key: &[u8] ) -> Vec<[u8;16]> {
    let mut blocks: Vec<[u8; 16]> = vec![];
    if (message.len() % 16) != 0 {
        message.push((15 - (message.len() % 16)) as u8);
        let size = message.len();
        for i in 0..(16 - (size % 16)) {
            message.push(0);
        }
    }
    for i in 0..(message.len() / 16) {
        let slice = <&[u8; 16]>::try_from(&message[(16*i)..(16*i+16)]);
        blocks.push(encrypt_block(slice.unwrap(), key));
    }
    return blocks;
}

pub fn ecb_decrypt(cipher_blocks: Vec<[u8;16]>, key: &[u8]) -> Vec<u8> {
    let mut message: Vec<u8> = vec![];
    for i in 0..cipher_blocks.len() {
        message.extend(decrypt_block(cipher_blocks[i], key));
    }
    let mut cnt: u8 = 0;

    loop {
        let num = message.pop().unwrap();
        if (num != 0) {
            if num == cnt { break }
            else { message.push(num as u8); break }
        }
        else { cnt += 1 }
    }
    return message;
}

pub fn cbc_encrypt(iv: [u8; 16], mut message: Vec<u8>, key: &[u8]) -> Vec<[u8; 16]> {
    let mut blocks: Vec<[u8; 16]> = vec![];

    if (message.len() % 16) != 0 {
        message.push((15 - (message.len() % 16)) as u8);
        let size = message.len();
        for i in 0..(16 - (size % 16)) {
            message.push(0);
        }
    }
    let slice = <[u8; 16]>::try_from(&message[(0)..(16)]).unwrap();
    blocks.push(encrypt_block(&xor_arrays(iv, slice), key));
    for i in 1..(message.len() / 16) {
        let slice = <[u8; 16]>::try_from(&message[16*i..(16*i+16)]).unwrap();
        blocks.push(encrypt_block(&xor_arrays(blocks[i-1], slice), key));
    }
    return blocks;
}

pub fn cbc_decrypt(iv: [u8; 16], blocks: Vec<[u8; 16]>, key: &[u8]) -> Vec<u8> {
    let mut message: Vec<u8> = vec![];
    message.extend(xor_arrays(iv, decrypt_block(blocks[0], key)));
    for i in 1..blocks.len() {
        message.extend(xor_arrays(blocks[i-1], decrypt_block(blocks[i], key)));
    }
    let mut cnt: u8 = 0;

    loop {
        let num = message.pop().unwrap();
        if (num != 0) {
            if num == cnt { break }
            else { message.push(num as u8); break }
        }
        else { cnt += 1 }
    }
    return message;
}

const l: usize = 1; // without padding, next algoritms work with each byte of message
pub fn cfb_encrypt(iv: [u8; 16], mut message: Vec<u8>, key: &[u8]) -> Vec<[u8; l]> {
    let mut cipher: Vec<[u8; l]> = vec![];
    let mut mes_slice: [u8; 16] = [0;16];
    for i in 0..l {
        mes_slice[i] = message[i];
    }
    let T_1 = (xor_arrays(encrypt_block(&iv, key), mes_slice));
    let mut curr_T: Vec<[u8; 16]> = vec![T_1];
    cipher.push(T_1[..l].try_into().unwrap());
    for i in 1..(message.len() / l) {
        let T_curr = curr_T.pop().unwrap();
        let slice: [u8; 16] = [&T_curr[l..], &cipher[i-1]].concat().try_into().unwrap();
        let mut mes_slice: [u8; 16] = [0;16];
        for j in 0..l {
            mes_slice[j] = message[i*l+j];
        }
        let T_i = (xor_arrays(encrypt_block(&slice, key), mes_slice));
        cipher.push(T_i[..l].try_into().unwrap());
        curr_T.push(T_i);
    }
    return cipher;
}

pub fn cfb_decrypt(iv: [u8; 16], cipher: Vec<[u8; l]>, key: &[u8]) -> Vec<u8> {
    let mut message: Vec<u8> = vec![];
    let mut ciph_slice: [u8; 16] = [0;16];
    for i in 0..l {
        ciph_slice[i] = cipher[0][i];
    }
    let T_1 = (xor_arrays(encrypt_block(&iv, key), ciph_slice));
    let mut curr_T: Vec<[u8; 16]> = vec![T_1];
    let x_i: [u8; l] = T_1[..l].try_into().unwrap();
    message.extend(x_i);
    for i in 1..((cipher.len()*cipher[0].len()) / l) {
        let T_curr = curr_T.pop().unwrap();
        let slice: [u8; 16] = [&T_curr[l..], &cipher[i-1]].concat().try_into().unwrap();
        let mut ciph_slice: [u8; 16] = [0;16];
        for j in 0..l {
            ciph_slice[j] = cipher[i][j];
        }
        let T_i = (xor_arrays(encrypt_block(&slice, key), ciph_slice));
        let x_i: [u8; l] = T_i[..l].try_into().unwrap();
        message.extend(x_i);
        curr_T.push(T_i);
    }
    return message;
}

pub fn ctr_encrypt(iv: [u8; 16], mut message: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let mut cipher: Vec<u8> = vec![];
    for i in 0..(message.len() / 16) {
        let str = format!("{:016x}", i);
        let mut decoded = [0; 8];
        hex::decode_to_slice(str, &mut decoded).expect("Decoding failed");
        let slice: [u8;16] = [&iv[0..8], &decoded].concat().try_into().unwrap();
        let mes_slice: [u8; 16] = message[16*i..(16*i+16)].try_into().unwrap();
        cipher.extend(xor_arrays(mes_slice, encrypt_block(&slice, key)));
    }
    if message.len() % 16 != 0 {
        let ctr = message.len() / 16;
        let str = format!("{:016x}", ctr);
        let mut decoded = [0; 8];
        hex::decode_to_slice(str, &mut decoded).expect("Decoding failed");
        let slice: [u8;16] = [&iv[0..8], &decoded].concat().try_into().unwrap();
        let T_curr = encrypt_block(&slice, key);
        for i in 0..(message.len() % 16) {
            cipher.push(message[16*ctr+i] ^ T_curr[i]);
        }
    }
    return cipher;
}

pub fn ctr_decrypt(iv: [u8; 16], mut cipher: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let mut message: Vec<u8> = vec![];
    for i in 0..(cipher.len() / 16) {
        let str = format!("{:016x}", i);
        let mut decoded = [0; 8];
        hex::decode_to_slice(str, &mut decoded).expect("Decoding failed");
        let slice: [u8;16] = [&iv[0..8], &decoded].concat().try_into().unwrap();
        let ciph_slice: [u8; 16] = cipher[16*i..(16*i+16)].try_into().unwrap();
        message.extend(xor_arrays(ciph_slice, encrypt_block(&slice, key)));
    }
    if cipher.len() % 16 != 0 {
        let ctr = cipher.len() / 16;
        let str = format!("{:016x}", ctr);
        let mut decoded = [0; 8];
        hex::decode_to_slice(str, &mut decoded).expect("Decoding failed");
        let slice: [u8;16] = [&iv[0..8], &decoded].concat().try_into().unwrap();
        let T_curr = encrypt_block(&slice, key);
        for i in 0..(cipher.len() % 16) {
            message.push(cipher[16*ctr+i] ^ T_curr[i]);
        }
    }
    return message;
}