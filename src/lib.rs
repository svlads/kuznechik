use anyhow::Result;
use log::*;
use std::io::{Read, Write};
use std::time::Instant;

static S: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219,
    147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129,
    28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212,
    211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112,
    14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154,
    199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
    128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115,
    30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
    165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217,
    231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113,
    103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244,
    180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
];

static INV_S: [u8; 256] = [
    0xa5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
    0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
    0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
    0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
    0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
    0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
    0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
    0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
    0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
    0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
    0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
    0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
    0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
    0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
    0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
    0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74,
];

static L: [u8; 16] = [
    1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148,
];

static POWS: [u8; 255] = [
    1, 2, 4, 8, 16, 32, 64, 128, 195, 69, 138, 215, 109, 218, 119, 238, 31, 62, 124, 248, 51, 102,
    204, 91, 182, 175, 157, 249, 49, 98, 196, 75, 150, 239, 29, 58, 116, 232, 19, 38, 76, 152, 243,
    37, 74, 148, 235, 21, 42, 84, 168, 147, 229, 9, 18, 36, 72, 144, 227, 5, 10, 20, 40, 80, 160,
    131, 197, 73, 146, 231, 13, 26, 52, 104, 208, 99, 198, 79, 158, 255, 61, 122, 244, 43, 86, 172,
    155, 245, 41, 82, 164, 139, 213, 105, 210, 103, 206, 95, 190, 191, 189, 185, 177, 161, 129,
    193, 65, 130, 199, 77, 154, 247, 45, 90, 180, 171, 149, 233, 17, 34, 68, 136, 211, 101, 202,
    87, 174, 159, 253, 57, 114, 228, 11, 22, 44, 88, 176, 163, 133, 201, 81, 162, 135, 205, 89,
    178, 167, 141, 217, 113, 226, 7, 14, 28, 56, 112, 224, 3, 6, 12, 24, 48, 96, 192, 67, 134, 207,
    93, 186, 183, 173, 153, 241, 33, 66, 132, 203, 85, 170, 151, 237, 25, 50, 100, 200, 83, 166,
    143, 221, 121, 242, 39, 78, 156, 251, 53, 106, 212, 107, 214, 111, 222, 127, 254, 63, 126, 252,
    59, 118, 236, 27, 54, 108, 216, 115, 230, 15, 30, 60, 120, 240, 35, 70, 140, 219, 117, 234, 23,
    46, 92, 184, 179, 165, 137, 209, 97, 194, 71, 142, 223, 125, 250, 55, 110, 220, 123, 246, 47,
    94, 188, 187, 181, 169, 145, 225,
];

static IN_POWS: [u8; 255] = [
    0, 1, 157, 2, 59, 158, 151, 3, 53, 60, 132, 159, 70, 152, 216, 4, 118, 54, 38, 61, 47, 133,
    227, 160, 181, 71, 210, 153, 34, 217, 16, 5, 173, 119, 221, 55, 43, 39, 191, 62, 88, 48, 83,
    134, 112, 228, 247, 161, 28, 182, 20, 72, 195, 211, 242, 154, 129, 35, 207, 218, 80, 17, 204,
    6, 106, 174, 164, 120, 9, 222, 237, 56, 67, 44, 31, 40, 109, 192, 77, 63, 140, 89, 185, 49,
    177, 84, 125, 135, 144, 113, 23, 229, 167, 248, 97, 162, 235, 29, 75, 183, 123, 21, 95, 73, 93,
    196, 198, 212, 12, 243, 200, 155, 149, 130, 214, 36, 225, 208, 14, 219, 189, 81, 245, 18, 240,
    205, 202, 7, 104, 107, 65, 175, 138, 165, 142, 121, 233, 10, 91, 223, 147, 238, 187, 57, 253,
    68, 51, 45, 116, 32, 179, 41, 171, 110, 86, 193, 26, 78, 127, 64, 103, 141, 137, 90, 232, 186,
    146, 50, 252, 178, 115, 85, 170, 126, 25, 136, 102, 145, 231, 114, 251, 24, 169, 230, 101, 168,
    250, 249, 100, 98, 99, 163, 105, 236, 8, 30, 66, 76, 108, 184, 139, 124, 176, 22, 143, 96, 166,
    74, 234, 94, 122, 197, 92, 199, 11, 213, 148, 13, 224, 244, 188, 201, 239, 156, 254, 150, 58,
    131, 52, 215, 69, 37, 117, 226, 46, 209, 180, 15, 33, 220, 172, 190, 42, 82, 87, 246, 111, 19,
    27, 241, 194, 206, 128, 203, 79,
];

fn multiply(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let inda = IN_POWS[a as usize - 1];
    let indb = IN_POWS[b as usize - 1];
    let mut indmul = inda as usize + indb as usize;
    if indmul >= 255 {
        indmul -= 255;
    }
    POWS[indmul]
}

fn simple_linear_transform(block: &mut [u8; 16], muls: &[[u8; 256]; 256]) {
    let mut cur = 0u8;
    for i in 0..16 {
        for first_ind in 0..16 {
            cur ^= muls[L[15 - first_ind] as usize][block[(first_ind + 16 - i) % 16] as usize];
        }
        block[15 - i] = cur;
        cur = 0u8;
    }
}

fn simple_inverse_linear_transform(block: &mut [u8; 16], muls: &[[u8; 256]; 256]) {
    let mut cur = 0u8;
    for i in 0..16 {
        for first_ind in 0..16 {
            cur ^= muls[L[first_ind] as usize][block[(first_ind + i) % 16] as usize];
        }
        block[i] = cur;
        cur = 0u8;
    }
}

fn linear_for_byte(index: usize, byte: u8, muls: &[[u8; 256]; 256]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[index] = byte;
    simple_linear_transform(&mut block, muls);
    block
}

fn inv_linear_for_byte(index: usize, byte: u8, muls: &[[u8; 256]; 256]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[index] = byte;
    simple_inverse_linear_transform(&mut block, muls);
    block
}

fn linear_transform(block: &mut [u8; 16], linears: &[[[u8; 16]; 256]; 16]) {
    let mut empty = [0u8; 16];
    for i in 0..16 {
        for first_ind in 0..16 {
            empty[first_ind] ^= linears[i][block[i] as usize][first_ind];
        }
    }
    block[..16].clone_from_slice(&empty[..16]);
}

fn inverse_linear_transform(block: &mut [u8; 16], inv_linears: &[[[u8; 16]; 256]; 16]) {
    let mut empty = [0u8; 16];
    for i in 0..16 {
        for first_ind in 0..16 {
            // cur ^= muls[L[first_ind] as usize][block[(first_ind + i) % 16] as usize];
            empty[first_ind] ^= inv_linears[i][block[i] as usize][first_ind];
        }
    }
    block[..16].clone_from_slice(&empty[..16]);
}

fn get_round_constants(linears: &[[[u8; 16]; 256]; 16]) -> [[u8; 16]; 32] {
    let mut constants = [[0u8; 16]; 32];
    for (i, constant) in constants.iter_mut().enumerate() {
        constant[15] = i as u8 + 1;
        linear_transform(constant, linears);
    }
    constants
}

fn generate_keys(key: &[u8; 32], linears: &[[[u8; 16]; 256]; 16]) -> [[u8; 16]; 10] {
    let mut round_keys: [[u8; 16]; 10] = [[0u8; 16]; 10];
    round_keys[0].copy_from_slice(&key[16..]);
    round_keys[1].copy_from_slice(&key[0..16]);

    let round_constants = get_round_constants(linears);
    for i in 1..5 {
        let mut left = round_keys[2 * (i - 1)];
        let mut right = round_keys[2 * (i - 1) + 1];
        let mut new_left = [0u8; 16];

        for ft_iter in 0..8 {
            for ind in 0..16 {
                new_left[ind] =
                    S[(left[ind] ^ round_constants[(i - 1) * 8 + ft_iter][ind]) as usize];
            }
            linear_transform(&mut new_left, linears);
            for ind in 0..16 {
                new_left[ind] ^= right[ind];
            }
            right = left;
            left = new_left;
        }
        round_keys[i * 2] = left;
        round_keys[i * 2 + 1] = right;
    }
    round_keys
}

fn encode_block(block: &mut [u8; 16], keys: &[[u8; 16]; 10], linears: &[[[u8; 16]; 256]; 16]) {
    for (i, round_key) in keys.iter().enumerate() {
        if i == 9 {
            for ind in 0..16 {
                block[ind] ^= round_key[ind];
            }
        } else {
            for ind in 0..16 {
                block[ind] = S[(block[ind] ^ round_key[ind]) as usize];
            }
            linear_transform(block, linears);
        }
    }
}

fn decode_block(block: &mut [u8; 16], keys: &[[u8; 16]; 10], inv_linears: &[[[u8; 16]; 256]; 16]) {
    for (i, round_key) in keys.iter().enumerate().rev() {
        if i == 9 {
            for ind in 0..16 {
                block[ind] ^= round_key[ind];
            }
        } else {
            inverse_linear_transform(block, inv_linears);
            for ind in 0..16 {
                block[ind] = INV_S[block[ind] as usize] ^ round_key[ind];
            }
        }
    }
}

pub fn encode<R: Read, W: Write>(mut input: R, mut output: W) -> Result<()> {
    let key: [u8; 32] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77,
    ];
    let mut muls = [[0u8; 256]; 256];
    let mut linears = [[[0u8; 16]; 256]; 16];
    let mut inv_linears = [[[0u8; 16]; 256]; 16];
    for i in 0u8..=255 {
        for j in 0u8..=255 {
            muls[i as usize][j as usize] = multiply(i, j);
        }
    }
    for i in 0..16 {
        for j in 0..=255 {
            linears[i][j] = linear_for_byte(i, j as u8, &muls);
            inv_linears[i][j] = inv_linear_for_byte(i, j as u8, &muls);
        }
    }
    let keys = generate_keys(&key, &linears);
    // let mut text = vec![1u8; 100 * 1024 * 1024];
    // let mut encoded = vec![1u8; 100 * 1024 * 1024];
    //
    // let start = Instant::now();
    // let mut block: [u8; 16] = Default::default();
    // for i in 0..100 * 1024 * 1024 / 16 {
    //     block.copy_from_slice(&text[i * 16..(i + 1) * 16]);
    //     encode_block(&mut block, &keys, &linears);
    //     for ind in 0..16 {
    //         encoded[16 * i + ind] = block[ind]
    //     }
    // }
    // info!("{}", start.elapsed().as_secs_f32());
    // info!("{}", encoded.last().unwrap());

    let mut text: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    ];
    encode_block(&mut text, &keys, &linears);
    info!("encoded = {:#2x?}", text);
    decode_block(&mut text, &keys, &inv_linears);
    info!("decoded = {:#2x?}", text);
    Ok(())
}

pub fn decode<R: Read, W: Write>(input: R, mut output: W) -> Result<()> {
    Ok(())
}
