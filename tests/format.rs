#[test]
fn base64_encode() {
    const TEST_B64_STRING: &str = "aGVsbG8=";

    // TEST_BYTES is hello
    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];

    assert_eq!(
        xck::format::base64_encode(&TEST_BYTES).unwrap(),
        TEST_B64_STRING
    );
}

#[test]
fn base64_decode() {
    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_B64_STRING: &str = "aGVsbG8=";

    assert_eq!(
        xck::format::base64_decode(TEST_B64_STRING).unwrap(),
        TEST_BYTES
    );
}


#[cfg(feature="alloc")]
#[test]
fn hex_encode() {
    // TEST_BYTES is hello
    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];
    
    const TEST_HEX_STRING:&str="68656c6c6f";

    assert_eq!(
        xck::format::hex_encode_alloc(&TEST_BYTES),
        TEST_HEX_STRING
    );
}
