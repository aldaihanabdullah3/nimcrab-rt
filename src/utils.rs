// utils.rs — djb2 hash + wide string helpers
#![allow(dead_code)]

pub const fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

pub const fn djb2_u16(s: &[u16]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

// Compare two null-terminated wide strings
pub unsafe fn wide_cmp(a: *const u16, b: &[u16]) -> bool {
    for (i, &bch) in b.iter().enumerate() {
        if *a.add(i) != bch { return false; }
    }
    true
}
