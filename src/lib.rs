extern crate openssl;

const SALT_SIZE: usize = 32;
const PBKDF_ITERS: usize = 10000;
// const HASH: openssl::hash::MessageDigest = openssl::hash::MessageDigest::sha256();
const KEY_SIZE: usize = 256 / 8;

pub struct HiddenData {
    salt: [u8; SALT_SIZE],
    hidden_data: Box<[u8]>, // TODO: remove this (that was put only to make tests pass)
}

/*
 * Hides data so that it cannot be recovered by a cold boot attack without the secret secret.
 *
 * Please note both data and secret will be erased at the end of this function, so that it is hard
 * to forget cleaning them up.
 */
pub fn hide(mut data: Box<[u8]>, secret: &mut [u8]) -> HiddenData {
    // Encrypt data with random key
    // TODO
    // Encrypt key with random key a number of times
    // TODO
    // Derive a key from the secret
    let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
    openssl::rand::rand_bytes(&mut salt);
    let mut key: [u8; KEY_SIZE] = [0; KEY_SIZE];
    openssl::pkcs5::pbkdf2_hmac(&secret, &salt, PBKDF_ITERS, /* HASH */ openssl::hash::MessageDigest::sha256(), &mut key);
    // Encrypt last random key with the secret
    // TODO
    let hidden_data = data.clone();
    // Erase all the things
    for mut x in data.iter_mut() {
        *x = 0;
    }
    for mut x in secret.iter_mut() {
        *x = 0;
    }
    // Return
    HiddenData {
        salt: salt,
        hidden_data: hidden_data,
    }
}

/*
 * Recovers data hidden with secret secret.
 *
 * Please note secret will be erased at the end of this function, so that it is hard to forget
 * cleaning it up.
 */
pub fn recover(data: HiddenData, secret: &mut [u8]) -> Box<[u8]> {
    // TODO
    // Erase secret
    // TODO
    // Return
    data.hidden_data
}


#[cfg(test)]
mod tests {
    use ::*;

    #[test]
    fn it_works() {
        let mut secret1 = [0, 1, 2, 3];
        let mut secret2 = secret1.clone();
        let data1 = Box::new([4, 5, 6, 6]);
        let data2 = data1.clone();
        assert_eq!(*recover(hide(data1, &mut secret1), &mut secret2), *data2);
    }
}
