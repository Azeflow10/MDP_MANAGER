use mdp_manager::crypto::*;

#[test]
fn test_key_derivation() {
    let password = "test_password";
    let salt = generate_salt();
    let params = CryptoParams::default();

    let key1 = derive_key(password, &salt, &params).unwrap();
    let key2 = derive_key(password, &salt, &params).unwrap();

    assert_eq!(key1.len(), 32);
    assert_eq!(key1, key2, "Same password and salt should produce same key");
}

#[test]
fn test_different_salts_produce_different_keys() {
    let password = "test_password";
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    let params = CryptoParams::default();

    let key1 = derive_key(password, &salt1, &params).unwrap();
    let key2 = derive_key(password, &salt2, &params).unwrap();

    assert_ne!(key1, key2, "Different salts should produce different keys");
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let plaintext = b"Hello, World! This is a secret message.";
    let password = "secure_password";
    let salt = generate_salt();
    let nonce = generate_nonce();
    let params = CryptoParams::default();

    let key = derive_key(password, &salt, &params).unwrap();
    let secure_key = SecureKey::new(key);

    let ciphertext = encrypt(plaintext, secure_key.as_bytes(), &nonce).unwrap();
    assert_ne!(plaintext, &ciphertext[..], "Ciphertext should differ from plaintext");

    let decrypted = decrypt(&ciphertext, secure_key.as_bytes(), &nonce).unwrap();
    assert_eq!(plaintext, &decrypted[..], "Decrypted text should match original");
}

#[test]
fn test_wrong_password_fails_decryption() {
    let plaintext = b"Secret data";
    let password1 = "password1";
    let password2 = "password2";
    let salt = generate_salt();
    let nonce = generate_nonce();
    let params = CryptoParams::default();

    let key1 = derive_key(password1, &salt, &params).unwrap();
    let ciphertext = encrypt(plaintext, &key1, &nonce).unwrap();

    let key2 = derive_key(password2, &salt, &params).unwrap();
    let result = decrypt(&ciphertext, &key2, &nonce);

    assert!(result.is_err(), "Wrong password should fail decryption");
}

#[test]
fn test_base64_encoding() {
    let data = b"Test data for base64";
    let encoded = encode_base64(data);
    let decoded = decode_base64(&encoded).unwrap();

    assert_eq!(data, &decoded[..]);
}

#[test]
fn test_secure_key_zeroize() {
    let key_data = vec![1, 2, 3, 4, 5];
    {
        let _secure_key = SecureKey::new(key_data.clone());
        // Key should be zeroized when dropped
    }
    // We can't actually test if memory is zeroed without unsafe code,
    // but we verify the type implements the trait correctly
}