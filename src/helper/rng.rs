/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub struct Csprng {
    rng: ChaCha20Rng,
}

impl Csprng {
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::from_os_rng(),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
        }
    }

    pub fn random_array<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0u8; N];
        self.fill_bytes(&mut buf);
        buf
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand::RngCore;
        self.rng.fill_bytes(dest);
    }
}

impl Default for Csprng {
    fn default() -> Self {
        Self::new()
    }
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut rng = Csprng::new();
    rng.random_array()
}
