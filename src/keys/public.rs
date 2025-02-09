use rand::Rng;
use rayon::prelude::ParallelSliceMut;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::keys::modulus;

#[derive(IntoBytes, FromBytes, Immutable)]
pub struct Public {
    modulo: i32,
    key: [i32; 2890],
    add: i32,
    dim: i32,
}

impl Public {
    pub fn new(modulo: i32, key: [i32; 2890], add: i32, dim: i32) -> Self {
        Self {
            modulo,
            key,
            add,
            dim,
        }
    }

    pub fn encrypt(&self, message: &String) -> Vec<u8> {
        let dim = (self.dim + 1) as usize;
        let message_chars: Vec<char> = message.chars().collect();
        let len = message_chars.len();
        let mut encrypted: Vec<i32> = vec![0; dim * len];
        let mut rng = rand::rng();

        encrypted.par_chunks_mut(dim).enumerate().for_each(| (i, chunk) | {
            let mut rng = rand::rng();
            let char_num = (message_chars[i] as i32) * self.add;

        });

        for (i, chr) in message.chars().into_iter().enumerate() {
            let chr_num = (chr as i32) * self.add;
            for _ in 0..rng.random_range(2..3) {
                let num = rng.random_range(0..self.dim * 10) as usize;
                let slice = (num * dim)..(num * dim) + dim;
                for (j, num) in self.key[slice].iter().enumerate() {
                    encrypted[(i * dim) + j] += num;
                }
            }
            encrypted[(i * dim) + dim - 1] =
                modulus(encrypted[(i * dim) + dim - 1] + chr_num, self.modulo)
        }

        encrypted.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {}
