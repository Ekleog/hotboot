extern crate openssl;

use openssl::hash::MessageDigest;
use openssl::symm::Cipher;

// TODO: Remove all unwrap's

const SALT_SIZE: usize = 32;
const PBKDF_ITERS: usize = 10000;
// const HASH: MessageDigest = MessageDigest::sha256();
// const CIPHER: Cipher = Cipher::aes_256_ctr();
const KEY_SIZE: usize = 256 / 8;
const IV_SIZE: usize = 16;

pub struct HiddenData {
    salt: Vec<u8>,
    blocks: Vec<EncryptedBlock>,
}

#[derive(Debug)]
struct EncryptedBlock {
    iv: [u8; IV_SIZE],
    data: Vec<u8>,
}

/**
 * Cleans up an array
 */
fn cleanup(mut data: Vec<u8>) {
    for x in data.iter_mut() {
        let y = x as *mut u8;
        unsafe { std::ptr::write_volatile(y, 0) }
    }
}

/**
 * Encrypts data with key returns a block that can be decrypted with the key
 *
 * data and key will be erased at the end of the function
 */
fn encrypt_and_destroy_key(data: Vec<u8>, key: Vec<u8>) -> EncryptedBlock {
    let mut iv = [0; IV_SIZE];
    openssl::rand::rand_bytes(&mut iv).unwrap();

    // Encrypt
    let enc = openssl::symm::encrypt(/* CIPHER */ Cipher::aes_256_ctr(), &key, Some(&iv), &data);

    // Clean up
    cleanup(data);
    cleanup(key);

    // Return
    EncryptedBlock { iv: iv, data: enc.unwrap() }
}

/**
 * Encrypts data and returns both the key used and a block that can be decrypted with the key
 *
 * data will be erased at the end of the function
 */
fn encrypt_and_destroy(data: Vec<u8>) -> (Vec<u8>, EncryptedBlock) {
    // Generate the parameters
    let mut key = vec![0; KEY_SIZE];
    openssl::rand::rand_bytes(&mut key).unwrap();
    let keyret = key.clone();

    // Return
    (keyret, encrypt_and_destroy_key(data, key))
}

/**
 * Decrypts encrypted block data with the key key
 *
 * The key will be erased at the end of the function
 */
fn decrypt(data: EncryptedBlock, key: Vec<u8>) -> Vec<u8> {
    let res = openssl::symm::decrypt(/* CIPHER */ Cipher::aes_256_ctr(), &key, Some(&data.iv), &data.data);
    cleanup(key);
    cleanup(data.data);
    res.unwrap()
}

/**
 * Derives a key from a secret and a salt
 *
 * The secret will be erased at the end of the function
 */
fn derive_key_salt(secret: Vec<u8>, salt: Vec<u8>) -> Vec<u8> {
    // Generate key
    let mut key = vec![0; KEY_SIZE];
    openssl::pkcs5::pbkdf2_hmac(&secret, &salt, PBKDF_ITERS, /* HASH */ MessageDigest::sha256(), &mut key).unwrap();

    // Clean up
    cleanup(secret);

    // Return
    key
}

/**
 * Derives a key from a secret, and returns a couple (salt, key)
 *
 * The secret will be erased at the end of the function
 */
fn derive_key(secret: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // Generate parameters
    let mut salt = vec![0; SALT_SIZE];
    openssl::rand::rand_bytes(&mut salt).unwrap();
    let saltret = salt.clone();

    // Return
    (saltret, derive_key_salt(secret, salt))
}

/**
 * Hides data so that it cannot be recovered by a cold boot attack without the secret secret.
 *
 * Please note both data and secret will be erased at the end of this function, so that it is hard
 * to forget cleaning them up.
 *
 * `iters` is the number of iterations to run, the number of bits that will be required uncorrupted
 * to recover the data with the secret is then approximately `384 * iters`
 */
pub fn hide(data: Vec<u8>, secret: Vec<u8>, iters: usize) -> HiddenData {
    let mut blocks = Vec::new();

    // Encrypt data with random key
    let (key, block) = encrypt_and_destroy(data);
    blocks.push(block);

    // Encrypt key with random key a number of times
    let mut oldkey = key;
    for _ in 0..iters {
        let (key, block) = encrypt_and_destroy(oldkey);
        blocks.push(block);
        oldkey = key;
    }

    // Encrypt last random key with the secret
    let (salt, key) = derive_key(secret);
    blocks.push(encrypt_and_destroy_key(oldkey, key));

    // Return
    HiddenData {
        salt: salt,
        blocks: blocks,
    }
}

/**
 * Recovers data hidden with secret secret.
 *
 * Please note secret will be erased at the end of this function, so that it is hard to forget
 * cleaning it up.
 */
pub fn recover(mut data: HiddenData, secret: Vec<u8>) -> Vec<u8> {
    // Decrypt random keys one by one
    let mut key = derive_key_salt(secret, data.salt);
    while let Some(data) = data.blocks.pop() {
        key = decrypt(data, key);
    }
    // Here, key is the last "key", ie. the stored data

    // Return
    key
}


#[cfg(test)]
mod tests {
    use ::*;

    #[test]
    fn it_works() {
        let secret1 = vec![0, 1, 2, 3];
        let secret2 = secret1.clone();
        let data1 = vec![4, 5, 6, 6];
        let data2 = data1.clone();
        assert_eq!(*recover(hide(data1, secret1, 100000), secret2), *data2);
    }
}
