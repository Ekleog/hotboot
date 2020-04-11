hotboot
=======

`hotboot` allows to secure private data with a weak secret, using as a
protection access control of the system and defense especially designed against
cold-boot attacks.


Usage
-----

```rust
let data: Vec<u8> = very_private_data();
let secret: Vec<u8> = get_secret_from_user();
let hidden = hotboot::hide(data, secret, 100000);

// `data` and `secret` no longer exist in memory
// A cold boot attack is highly unlikely to succeed in retrieving `data`, even
// if `secret` is known

let secret: Vec<u8> = get_secret_from_user();
let recovered = hotboot::recover(hidden, secret);
// `recovered` is the same as `data` was
```

Threat model
------------

The threat model is that of a physical attacker who attacks a
weak-secret-protected data using a cold boot attack.

The special use case this was designed for is screenlockers: the screen
unlocking password may not be strong, but there are timing delays that make
brute-force impractical. The use of hotboot to protect the secure data in memory
with the unlocking password allows to also be secure against a cold boot attack.


Design
------

During a cold boot attack, some bits get corrupted. The aim of hotboot is to
minimize the ratio of bits that have to get corrupted to make it impossible to
recover the private data.

In order to do so, it encrypts the data with a random key, then encrypts the
random key with another random key, iterates a number of times, and then
encrypts the last random key with a key derived from the password.

If any bit in this chain is corrupted, garbage will be found at the end, without
being able to know which bit caused the issue.

The choice of cryptographic primitives is AES256-CTR for the encryption (with a
random 128-bits IV and a random 256-bits key, making for 384 bits that have not
to be corrupted to decrypt one step), and PBKDF2-SHA256 with 10000 iterations
for initial key derivation.


Troubleshooting
---------------

Be it a support request, a bug, a lack in documentation or anything else that
doesn't just work as expected, please report it as a [GitHub
issue](https://github.com/Ekleog/hotboot/issues/new).


History
-------

 * 2020-04-12: 0.1.1 released, uses a newer openssl
 * 2017-03-05: 0.1.0 released
 * 2017-03-04: Project launch


License
-------

`hotboot` is licensed under GPLv3, please see the file called `LICENSE.md`.
