//! SHA-256, HMAC over it, and PBKDF2 over that: enough to store a password
//! as something other than the password.
//!
//! In-house for the same reason as everything else in the image. It is short,
//! and tested against the published vectors.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self { state: INITIAL, block: [0; 64], filled: 0, length: 0 }
    }
}

impl Sha256 {
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.length += bytes.len() as u64;
        while !bytes.is_empty() {
            let take = (64 - self.filled).min(bytes.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&bytes[..take]);
            self.filled += take;
            bytes = &bytes[take..];
            if self.filled == 64 {
                compress(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.length * 8;
        self.update(&[0x80]);
        while self.filled != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());

        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (word, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(add);
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::default();
    hash.update(bytes);
    hash.finish()
}

/// HMAC-SHA-256, with the key already padded into its inner and outer states
/// so PBKDF2 does not redo that every iteration.
#[derive(Clone)]
struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            block[..32].copy_from_slice(&sha256(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let (mut inner, mut outer) = (Sha256::default(), Sha256::default());
        inner.update(&block.map(|b| b ^ 0x36));
        outer.update(&block.map(|b| b ^ 0x5c));
        Self { inner, outer }
    }

    fn mac(&self, message: &[&[u8]]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        for part in message {
            inner.update(part);
        }
        let mut outer = self.outer.clone();
        outer.update(&inner.finish());
        outer.finish()
    }
}

/// PBKDF2-HMAC-SHA-256, one 32-byte block.
pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let hmac = Hmac::new(password);
    let mut u = hmac.mac(&[salt, &1u32.to_be_bytes()]);
    let mut key = u;
    for _ in 1..iterations {
        u = hmac.mac(&[&u]);
        for (k, b) in key.iter_mut().zip(u) {
            *k ^= b;
        }
    }
    key
}

/// Equal, in time that depends only on the length.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}
