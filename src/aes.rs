
use crate::{bytes_to_matrix, inv_mix_columns, matrix_to_bytes, mix_columns, shift_rows, sub_bytes};
use crate::aes::{inv_shift_rows, inv_sub_bytes, r_con, s_box};


fn expand_key_128(key: &[u8]) -> Vec<[u8; 4]> {
    let mut key_columns: [[u8; 4]; 44] = [[1;4]; 44];

    for i in 0..4 {
        for j in 0..4 {
            key_columns[i][j] = key[4*i+j];
        }
    }

    for i in 1..11 {
        (key_columns[4*i][0], key_columns[4*i][1], key_columns[4*i][2], key_columns[4*i][3]) =
            (s_box[key_columns[4*i-1][1] as usize], s_box[key_columns[4*i-1][2] as usize],
             s_box[key_columns[4*i-1][3] as usize], s_box[key_columns[4*i-1][0] as usize]);
        key_columns[4*i][0] ^= r_con[i];
        for j in 0..4 {
            key_columns[4*i][j] ^= key_columns[4*(i-1)][j];
        }
        for j in 1..4 {
            for k in 0..4 {
                key_columns[4*i+j][k] = key_columns[4*(i-1)+j][k] ^ key_columns[4*i+j-1][k];
            }
        }
    }
    return key_columns.to_vec();
}

pub fn expand_key_192(key: &[u8]) -> Vec<[u8; 4]> {
    let mut key_columns: [[u8; 4]; 52] = [[1;4]; 52];

    for i in 0..6 {
        for j in 0..4 {
            key_columns[i][j] = key[4*i+j];
        }
    }

    for i in 1..9 {
        (key_columns[6*i][0], key_columns[6*i][1], key_columns[6*i][2], key_columns[6*i][3]) =
            (s_box[key_columns[6*i-1][1] as usize], s_box[key_columns[6*i-1][2] as usize],
             s_box[key_columns[6*i-1][3] as usize], s_box[key_columns[6*i-1][0] as usize]);
        key_columns[6*i][0] ^= r_con[i];
        for j in 0..4 {
            key_columns[6*i][j] ^= key_columns[6*(i-1)][j];
        }
        for j in 1..6 {
            if 6*i+j == 52 {break}
            for k in 0..4 {
                key_columns[6*i+j][k] = key_columns[6*(i-1)+j][k] ^ key_columns[6*i+j-1][k];
            }
        }
    }
    return key_columns.to_vec();
}

pub fn expand_key_256(key: &[u8]) -> Vec<[u8; 4]> {
    let mut key_columns: [[u8; 4]; 60] = [[1;4]; 60];

    for i in 0..8 {
        for j in 0..4 {
            key_columns[i][j] = key[4*i+j];
        }
    }

    for i in 1..8 {
        (key_columns[8*i][0], key_columns[8*i][1], key_columns[8*i][2], key_columns[8*i][3]) =
            (s_box[key_columns[8*i-1][1] as usize], s_box[key_columns[8*i-1][2] as usize],
             s_box[key_columns[8*i-1][3] as usize], s_box[key_columns[8*i-1][0] as usize]);
        key_columns[8*i][0] ^= r_con[i];
        for j in 0..4 {
            key_columns[8*i][j] ^= key_columns[8*(i-1)][j];
        }
        for j in 1..8 {
            if 8*i+j == 60 {break}
            if (8*i+j) % 4 == 0 {
                for k in 0..4 {
                    key_columns[8*i+j][k] = key_columns[8*(i-1)+j][k] ^ s_box[key_columns[8*i+j-1][k] as usize];
                }
                continue;
            }
            for k in 0..4 {
                key_columns[8*i+j][k] = key_columns[8*(i-1)+j][k] ^ key_columns[8*i+j-1][k];
            }
        }
    }
    return key_columns.to_vec();
}

pub fn encrypt_block(message: &[u8;16], key: &[u8]) -> [u8; 16] {
    let mut plain_state = bytes_to_matrix(message);
    let n_rounds = if key.len() == 16 {10} else  if key.len() == 24 {12} else if key.len() == 32 {14} else { 0 };
    let key_columns = if key.len() == 16 {expand_key_128(key)} else if key.len() == 24 {expand_key_192(key)}
        else if key.len() == 32 {expand_key_256(key)} else { vec![[1;4]] } ;
    for i in 0..4 {
        for j in 0..4 {
           plain_state[i][j] ^= key_columns[i][j];
        }
    }

    for i in 1..n_rounds {

        sub_bytes(&mut plain_state);
        shift_rows(&mut plain_state);
        mix_columns(&mut plain_state);
        for j in 0..4 {
            for k in 0..4 {
                plain_state[j][k] ^= key_columns[4 * i + j][k];
            }
        }
    }

    sub_bytes(&mut plain_state);
    shift_rows(&mut plain_state);
    for i in 0..4 {
        for j in 0..4 {
            plain_state[i][j] ^= key_columns[4*10+i][j];
        }
    }
    return matrix_to_bytes(plain_state);
}

pub fn decrypt_block(cipher: [u8;16], key: &[u8]) -> [u8; 16] {
    let mut ciphertext = bytes_to_matrix(&cipher);
    let n_rounds = if key.len() == 16 {10} else  if key.len() == 24 {12} else if key.len() == 32 {14} else { 0 };
    let key_columns = if key.len() == 16 {expand_key_128(key)} else if key.len() == 24 {expand_key_192(key)}
        else if key.len() == 32 {expand_key_256(key)} else { vec![[1;4]] };
    for i in 0..4 {
        for j in 0..4 {
            ciphertext[i][j] ^= key_columns[4*10+i][j];
        }
    }

    inv_shift_rows(&mut ciphertext);
    inv_sub_bytes(&mut ciphertext);

    for i in (1..n_rounds).rev() {
        for j in 0..4 {
            for k in 0..4 {
                ciphertext[j][k] ^= key_columns[4*i+j][k];
            }
        }
        inv_mix_columns(&mut ciphertext);
        inv_shift_rows(&mut ciphertext);
        inv_sub_bytes(&mut ciphertext);

    }
    let mut message: [u8;16] = [0;16];
    for i in 0..4 {
        for j in 0..4 {
            message[4*i+j] = ciphertext[i][j] ^ key_columns[i][j];
        }
    }
    return message;
}