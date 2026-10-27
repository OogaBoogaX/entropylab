//! Deterministic PRNG (xorshift64*) and FNV-1a hashing for per-case seeds.

/// xorshift64* — small, fast, deterministic, and good enough for image noise.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        // xorshift64* must never be seeded with zero.
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    pub fn from_name(name: &str) -> Self {
        Self::new(fnv1a(name))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    /// Uniform in `[0, n)`. Returns 0 for `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// FNV-1a over the UTF-8 bytes of `s`.
pub fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        let mut equal = 0;
        for _ in 0..64 {
            if a.next_u64() == b.next_u64() {
                equal += 1;
            }
        }
        assert!(equal < 2, "two seeds produced {equal} equal draws");
    }

    #[test]
    fn zero_seed_is_not_stuck() {
        let mut rng = Rng::new(0);
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(first, 0);
        assert_ne!(first, second);
    }
}
