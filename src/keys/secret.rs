use std::char::from_u32;
use std::fmt::{Display, Formatter};

use rand::Rng;
use rayon::prelude::*;
use zerocopy::{FromBytes, IntoBytes, Immutable};

use crate::keys::{MAX_CHR, modulus};
use crate::keys::public::Public;

#[derive(serde::Deserialize, serde::Serialize, IntoBytes, FromBytes, Immutable)]
pub struct Secret16 {
    pub(crate) key: [i32; 16],
    pub(crate) modulo: i32,
    pub(crate) add: i32,
}

impl Secret16 {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let mut key = [0; 16];
        let modulo = rng.random_range(11120640..111206400);
        let add: i32 = modulo / MAX_CHR;
        for i in 0..16 {
            key[i] = rng.random_range(-4096..4096);
        }

        Secret16 { key, modulo, add }
    }

    pub fn generate_public_key(&self) -> Public {
        let mut rng = rand::rng();
        let dim = self.key.len();
        let len = dim * 10;
        let add = self.add;
        let mut key: Vec<Vec<i32>> = vec![vec![0; dim + 1]; len];
        let max_fuzz = add / 10;
        let neg_fuzz = -1 * max_fuzz;

        for i in 0..len {
            for j in 0..dim {
                key[i][j] = rng.random_range(-4096..4096);
            }
        }

        for i in 0..len {
            let equation = &mut key[i];
            let mut answer: i32 = 0;
            for j in 0..dim {
                answer += equation[j] * self.key[j];
            }
            equation[dim] = modulus(answer + rng.random_range(neg_fuzz..max_fuzz), self.modulo);
        }

        Public::new(self.modulo, key, add, max_fuzz, dim,)
    }

    pub fn decrypt(&self, message: &[u8]) -> String {
        let message: &[i32] = FromBytes::ref_from_bytes(message).unwrap();
        let dim = self.key.len() + 1;
        let len = message.len() / dim;
        let mut answers: Vec<u32> = vec![0; len];
        let mut decrypted = String::with_capacity(len);

        answers
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, expected)| {
                let chr_answer: i32 = self
                    .key
                    .iter()
                    .enumerate()
                    .map(|(j, num)| num * message[(i * dim) + j])
                    .sum();

                *expected = (modulus(message[(i * dim) + dim - 1] - chr_answer, self.modulo) as f32
                    / self.add as f32)
                    .round() as u32;
            });

        for answer in answers {
            decrypted.push(from_u32(answer).unwrap_or_else(|| '💩'));
        }

        decrypted
    }
}

impl Display for Secret16 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.key.len() > 10 {
            let key = &self.key[..10];
            let output = format!("Secret {{ {:?}... }}", key)
                .replace("[", "")
                .replace("]", "");

            write!(f, "{}", output)
        } else {
            let output = format!("Secret {{ {:?} }}", self.key)
                .replace("[", "")
                .replace("]", "");

            write!(f, "{}", output)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::public::Public;

    use super::*;

    #[test]
    fn test_decryption() {
        let secret = Secret16::new();
        let public = secret.generate_public_key();

        let message = "Hello World".to_string();

        let encrypted = public.encrypt(&message);
        let decrypted = secret.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decryption_utf8() {
        let secret = Secret16::new();
        let public = secret.generate_public_key();

        let message = "こんにちは世界".to_string();

        let encrypted = public.encrypt(&message);
        let decrypted = secret.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn secret_creation() {
        let secret = Secret16::new();
        assert_eq!(secret.key.len(), 16);

        let mod_range = 11120640..111206400;
        assert!(mod_range.contains(&secret.modulo));

        let key_range = -32768..32768;
        for num in secret.key.iter() {
            assert!(key_range.contains(num));
        }
    }
}
