// cargo test --package xck --test hash --  --nocapture
// cargo test --package xck --test hash -- sha256 --exact --nocapture

#[test]
fn sha256() {
    const TEST_DIGEST: [u8; 32] = [
        44, 242, 77, 186, 95, 176, 163, 14, 38, 232, 59, 42, 197, 185, 226, 158, 27, 22, 30, 92,
        31, 167, 66, 94, 115, 4, 51, 98, 147, 139, 152, 36,
    ];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    assert_eq!(xck::hash::sha256(&TEST_MESSAGE), TEST_DIGEST);
}

#[test]
fn sha512() {
    const TEST_DIGEST: [u8; 64] = [
        155, 113, 210, 36, 189, 98, 243, 120, 93, 150, 212, 106, 211, 234, 61, 115, 49, 155, 251,
        194, 137, 12, 170, 218, 226, 223, 247, 37, 25, 103, 60, 167, 35, 35, 195, 217, 155, 165,
        193, 29, 124, 122, 204, 110, 20, 184, 197, 218, 12, 70, 99, 71, 92, 46, 92, 58, 222, 244,
        111, 115, 188, 222, 192, 67,
    ];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    assert_eq!(xck::hash::sha512(&TEST_MESSAGE), TEST_DIGEST);
}

#[test]
fn sha512_256() {
    const TEST_DIGEST: [u8; 32] = [
        227, 13, 135, 207, 162, 167, 93, 181, 69, 234, 196, 214, 27, 175, 151, 3, 102, 168, 53,
        124, 127, 114, 250, 149, 181, 45, 10, 204, 182, 152, 241, 58,
    ];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    assert_eq!(xck::hash::sha512_256(&TEST_MESSAGE), TEST_DIGEST);
}

#[test]
fn blake3() {
    const TEST_DIGEST: [u8; 32] = [
        234, 143, 22, 61, 179, 134, 130, 146, 94, 68, 145, 197, 229, 141, 75, 179, 80, 110, 248,
        193, 78, 183, 138, 134, 233, 8, 197, 98, 74, 103, 32, 15,
    ];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    assert_eq!(xck::hash::blake3(&TEST_MESSAGE), TEST_DIGEST);
}

#[test]
fn blake3_kdf() {
    // 0123 = [48, 49, 50, 51]
    const TEST_KEY_MATERIAL: [u8; 4] = [48, 49, 50, 51];

    const TEST_CONTEXT: &str = "hello";

    const TEST_DIGEST: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    assert_eq!(
        xck::hash::blake3_kdf(TEST_CONTEXT, &TEST_KEY_MATERIAL),
        TEST_DIGEST
    );
}

#[test]
fn blake3_mac() {
    const TEST_KEY: [u8; 32] = [
        57, 175, 86, 245, 102, 95, 243, 137, 254, 235, 187, 7, 87, 88, 175, 190, 102, 82, 188, 163,
        54, 51, 85, 130, 172, 177, 0, 252, 130, 32, 174, 81,
    ];

    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_MAC: [u8; 32] = [
        253, 225, 188, 78, 162, 61, 152, 1, 150, 120, 181, 134, 46, 143, 205, 116, 195, 249, 169,
        227, 50, 176, 112, 41, 42, 247, 180, 199, 34, 87, 76, 38,
    ];

    assert_eq!(
        xck::hash::blake3_mac(&TEST_KEY, &TEST_MESSAGE),
        TEST_MAC
    );
}
