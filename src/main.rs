mod appendix;
mod aes;
mod mods;

use crate::mods::{ecb_encrypt, ecb_decrypt, cbc_decrypt, cbc_encrypt, cfb_decrypt, cfb_encrypt, ctr_decrypt, ctr_encrypt};


fn main() {
    let text = b"\x33\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x01\x02\x03";
    let key  = b"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
    let key_2 = b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
    println!("{:?}", text.to_vec());
    println!("{:?}", ecb_decrypt(ecb_encrypt(text.to_vec(), key_2), key_2)); //return text
    println!("{:?}", ecb_decrypt(ecb_encrypt(text.to_vec(), key), key));
}
