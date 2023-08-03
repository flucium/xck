#[test]
#[cfg(feature = "alloc")]
fn aes_256_gcm_encrypt_alloc() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_NONCE: [u8; 12] = [237, 234, 221, 165, 161, 138, 43, 236, 203, 229, 63, 230];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_CIPHER: [u8; 21] = [
        137, 100, 3, 0, 89, 137, 198, 236, 253, 242, 215, 211, 190, 34, 227, 115, 73, 197, 139,
        194, 158,
    ];

    assert_eq!(
        xck::symmetric::aes_256_gcm_encrypt_alloc(&TEST_KEY, &TEST_NONCE, &[], &TEST_MESSAGE).unwrap(),
        TEST_CIPHER
    );
}

#[test]
#[cfg(feature = "alloc")]
fn aes_256_gcm_decrypt_alloc() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_NONCE: [u8; 12] = [237, 234, 221, 165, 161, 138, 43, 236, 203, 229, 63, 230];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_CIPHER: [u8; 21] = [
        137, 100, 3, 0, 89, 137, 198, 236, 253, 242, 215, 211, 190, 34, 227, 115, 73, 197, 139,
        194, 158,
    ];

    assert_eq!(
        xck::symmetric::aes_256_gcm_decrypt_alloc(&TEST_KEY, &TEST_NONCE, &[], &TEST_CIPHER).unwrap(),
        TEST_MESSAGE
    );
}

#[test]
#[cfg(feature = "alloc")]
fn xchacha20_poly1305_decrypt() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_NONCE: [u8; 24] = [
        38, 51, 16, 243, 54, 82, 44, 250, 194, 172, 143, 105, 171, 148, 115, 75, 219, 222, 138,
        150, 202, 46, 215, 4,
    ];

    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_CIPHER: [u8; 21] = [
        10, 252, 200, 7, 242, 109, 58, 75, 122, 103, 187, 179, 209, 151, 175, 118, 200, 13, 88, 81,
        22,
    ];

    assert_eq!(
        xck::symmetric::xchacha20_poly1305_decrypt_alloc(&TEST_KEY, &TEST_NONCE, &[], &TEST_CIPHER)
            .unwrap(),
        TEST_MESSAGE
    );
}

#[test]
#[cfg(feature = "alloc")]
fn xchacha20_poly1305_encrypt_alloc() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_NONCE: [u8; 24] = [
        38, 51, 16, 243, 54, 82, 44, 250, 194, 172, 143, 105, 171, 148, 115, 75, 219, 222, 138,
        150, 202, 46, 215, 4,
    ];

    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_CIPHER: [u8; 21] = [
        10, 252, 200, 7, 242, 109, 58, 75, 122, 103, 187, 179, 209, 151, 175, 118, 200, 13, 88, 81,
        22,
    ];

    assert_eq!(
        xck::symmetric::xchacha20_poly1305_encrypt_alloc(&TEST_KEY, &TEST_NONCE, &[], &TEST_MESSAGE)
            .unwrap(),
        TEST_CIPHER
    );
}

#[test]
#[cfg(feature = "alloc")]
fn chacha20_poly1305_decrypt_alloc() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_NONCE: [u8; 12] = [237, 234, 221, 165, 161, 138, 43, 236, 203, 229, 63, 230];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_CIPHER: [u8; 21] = [
        30, 117, 55, 72, 38, 100, 128, 57, 130, 159, 56, 119, 83, 106, 118, 249, 117, 18, 77, 97,
        79,
    ];

    assert_eq!(
        xck::symmetric::chacha20_poly1305_decrypt_alloc(&TEST_KEY, &TEST_NONCE, &[], &TEST_CIPHER)
            .unwrap(),
        TEST_MESSAGE
    );
}


#[test]
#[cfg(feature = "alloc")]
fn chacha20_poly1305_encrypt_alloc() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_NONCE: [u8; 12] = [237, 234, 221, 165, 161, 138, 43, 236, 203, 229, 63, 230];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_CIPHER: [u8; 21] = [
        30, 117, 55, 72, 38, 100, 128, 57, 130, 159, 56, 119, 83, 106, 118, 249, 117, 18, 77, 97,
        79,
    ];

    assert_eq!(
        xck::symmetric::chacha20_poly1305_encrypt_alloc(&TEST_KEY, &TEST_NONCE, &[], &TEST_MESSAGE)
            .unwrap(),
        TEST_CIPHER
    );
}
