/*
 * Copyright (C) 2016  Leo Gaspard
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*!
 * hotboot
 * =======
 *
 * `hotboot` allows to secure private data with a weak secret, using as a
 * protection access control of the system and defense especially designed against
 * cold-boot attacks.
 *
 *
 * Usage
 * -----
 *
 * ```
 * # fn get_secret_from_user() -> Vec<u8> { vec![1, 5, 32, 46, 152] }
 * # fn very_private_data() -> Vec<u8> { vec![9, 12, 42, 10, 43, 19, 140, 158] }
 *
 * let data: Vec<u8> = very_private_data();
 * let secret: Vec<u8> = get_secret_from_user();
 * let hidden = hotboot::hide(data, secret, 100000).unwrap();
 *
 * // `data` and `secret` no longer exist in memory
 * // A cold boot attack is highly unlikely to succeed in retrieving `data`, even
 * // if `secret` is known
 *
 * let secret: Vec<u8> = get_secret_from_user();
 * let recovered = hotboot::recover(hidden, secret).unwrap();
 * // `recovered` is the same as `data` was
 *
 * # assert_eq!(recovered, very_private_data());
 * ```
 *
 * Threat model
 * ------------
 *
 * The threat model is that of a physical attacker who attacks a
 * weak-secret-protected data using a cold boot attack.
 *
 * The special use case this was designed for is screenlockers: the screen
 * unlocking password may not be strong, but there are timing delays that make
 * brute-force impractical. The use of hotboot to protect the secure data in memory
 * with the unlocking password allows to also be secure against a cold boot attack.
 *
 *
 * Design
 * ------
 *
 * During a cold boot attack, some bits get corrupted. The aim of hotboot is to
 * minimize the ratio of bits that have to get corrupted to make it impossible to
 * recover the private data.
 *
 * In order to do so, it encrypts the data with a random key, then encrypts the
 * random key with another random key, iterates a number of times, and then
 * encrypts the last random key with a key derived from the password.
 *
 * If any bit in this chain is corrupted, garbage will be found at the end, without
 * being able to know which bit caused the issue.
 *
 * The choice of cryptographic primitives is AES256-CTR for the encryption (with a
 * random 128-bits IV and a random 256-bits key, making for 384 bits that have not
 * to be corrupted to decrypt one step), and PBKDF2-SHA256 with 10000 iterations
 * for initial key derivation.
 *
 *
 * Troubleshooting
 * ---------------
 *
 * Be it a support request, a bug, a lack in documentation or anything else that
 * doesn't just work as expected, please report it as a [GitHub
 * issue](https://github.com/Ekleog/hotboot/issues/new).
 *
 *
 * History
 * -------
 *
 *  * 2017-03-05: 0.1.0 released
 *  * 2017-03-04: Project launch
 *
 *
 * License
 * -------
 *
 * `hotboot` is licensed under GPLv3, please see the file called `LICENSE.md`.
 */

#![warn(missing_docs)]

extern crate openssl;

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::symm::Cipher;

const SALT_SIZE: usize = 32;
const PBKDF_ITERS: usize = 10000;
// const HASH: MessageDigest = MessageDigest::sha256();
// const CIPHER: Cipher = Cipher::aes_256_ctr();
const KEY_SIZE: usize = 256 / 8;
const IV_SIZE: usize = 16;

/**
 * Opaque struct encapsulating data encrypted with a secret.
 *
 * See `hide` and `recover` for information on how to hide or recover data
 */
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
 * Error that can be raised by a failed `hide` or `recover` call.
 */
#[derive(Debug)]
pub enum Error {
    /// Error occuring during encryption
    EncryptionError(ErrorStack),
    /// Error occuring during decryption
    DecryptionError(ErrorStack),
    /// Error occuring while trying to gather random bytes
    RandomBytesError(ErrorStack),
    /// Error occuring while trying to derive a key from the secret
    KeyDerivationError(ErrorStack),
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
fn encrypt_and_destroy_key(data: Vec<u8>, key: Vec<u8>) -> Result<EncryptedBlock, Error> {
    let mut iv = [0; IV_SIZE];
    openssl::rand::rand_bytes(&mut iv).map_err(Error::RandomBytesError)?;

    // Encrypt
    let enc =
        openssl::symm::encrypt(/* CIPHER */ Cipher::aes_256_ctr(), &key, Some(&iv), &data)
        .map_err(Error::EncryptionError)?;

    // Clean up
    cleanup(data);
    cleanup(key);

    // Return
    Ok(EncryptedBlock { iv: iv, data: enc })
}

/**
 * Encrypts data and returns both the key used and a block that can be decrypted with the key
 *
 * data will be erased at the end of the function
 */
fn encrypt_and_destroy(data: Vec<u8>) -> Result<(Vec<u8>, EncryptedBlock), Error> {
    // Generate the parameters
    let mut key = vec![0; KEY_SIZE];
    openssl::rand::rand_bytes(&mut key).map_err(Error::RandomBytesError)?;
    let keyret = key.clone();

    // Return
    Ok((keyret, encrypt_and_destroy_key(data, key)?))
}

/**
 * Decrypts encrypted block data with the key key
 *
 * The key will be erased at the end of the function
 */
fn decrypt(data: EncryptedBlock, key: Vec<u8>) -> Result<Vec<u8>, Error> {
    let res =
        openssl::symm::decrypt(/* CIPHER */ Cipher::aes_256_ctr(), &key, Some(&data.iv), &data.data)
        .map_err(Error::DecryptionError)?;
    cleanup(key);
    cleanup(data.data);
    Ok(res)
}

/**
 * Derives a key from a secret and a salt
 *
 * The secret will be erased at the end of the function
 */
fn derive_key_salt(secret: Vec<u8>, salt: Vec<u8>) -> Result<Vec<u8>, Error> {
    // Generate key
    let mut key = vec![0; KEY_SIZE];
    openssl::pkcs5::pbkdf2_hmac(&secret, &salt, PBKDF_ITERS, /* HASH */ MessageDigest::sha256(), &mut key)
        .map_err(Error::KeyDerivationError)?;

    // Clean up
    cleanup(secret);

    // Return
    Ok(key)
}

/**
 * Derives a key from a secret, and returns a couple (salt, key)
 *
 * The secret will be erased at the end of the function
 */
fn derive_key(secret: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Generate parameters
    let mut salt = vec![0; SALT_SIZE];
    openssl::rand::rand_bytes(&mut salt).map_err(Error::RandomBytesError)?;
    let saltret = salt.clone();

    // Return
    Ok((saltret, derive_key_salt(secret, salt)?))
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
pub fn hide(data: Vec<u8>, secret: Vec<u8>, iters: usize) -> Result<HiddenData, Error> {
    let mut blocks = Vec::new();

    // Encrypt data with random key
    let (key, block) = encrypt_and_destroy(data)?;
    blocks.push(block);

    // Encrypt key with random key a number of times
    let mut oldkey = key;
    for _ in 0..iters {
        let (key, block) = encrypt_and_destroy(oldkey)?;
        blocks.push(block);
        oldkey = key;
    }

    // Encrypt last random key with the secret
    let (salt, key) = derive_key(secret)?;
    blocks.push(encrypt_and_destroy_key(oldkey, key)?);

    // Return
    Ok(HiddenData {
        salt: salt,
        blocks: blocks,
    })
}

/**
 * Recovers data hidden with secret secret.
 *
 * Please note secret will be erased at the end of this function, so that it is hard to forget
 * cleaning it up.
 */
pub fn recover(mut data: HiddenData, secret: Vec<u8>) -> Result<Vec<u8>, Error> {
    // Decrypt random keys one by one
    let mut key = derive_key_salt(secret, data.salt)?;
    while let Some(data) = data.blocks.pop() {
        key = decrypt(data, key)?;
    }
    // Here, key is the last "key", ie. the stored data

    // Return
    Ok(key)
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
        assert_eq!(*recover(hide(data1, secret1, 100000).unwrap(), secret2).unwrap(), *data2);
    }
}
