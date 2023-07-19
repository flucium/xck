#[test]
fn aes_256_gcm_encrypt() {
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
        xck::symmetric::aes_256_gcm_encrypt(&TEST_KEY, &TEST_NONCE, &[], &TEST_MESSAGE).unwrap(),
        TEST_CIPHER
    );
}

#[test]
fn aes_256_gcm_decrypt() {
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
        xck::symmetric::aes_256_gcm_decrypt(&TEST_KEY, &TEST_NONCE, &[], &TEST_CIPHER).unwrap(),
        TEST_MESSAGE
    );
}
