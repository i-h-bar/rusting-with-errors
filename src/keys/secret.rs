use std::char::from_u32;
use std::fmt::{Display, Formatter};

use rand::Rng;
use rayon::prelude::*;
use zerocopy::{CastError, FromBytes, Immutable, IntoBytes};

use crate::keys::public::Public;
use crate::keys::{modulus, MAX_CHR};

#[derive(IntoBytes, FromBytes, Immutable)]
pub struct Secret16 {
    key: [i32; 16],
    modulo: i32,
    add: i32,
    dim: i32,
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

        Secret16 {
            key,
            modulo,
            add,
            dim: 16,
        }
    }

    pub fn generate_public_key(&self) -> Public {
        let mut rng = rand::rng();
        let add = self.add;
        let mut key: [i32; 2890] = [0; 2890];
        let max_fuzz = add / 10;
        let neg_fuzz = -1 * max_fuzz;

        for i in 0..key.len() {
            key[i] = rng.random_range(-4096..4096);
        }

        for i in 0..170 {
            let equation = &mut key[i * 17..(i * 17) + 17];
            let mut answer: i32 = 0;
            for j in 0..self.dim as usize {
                answer += equation[j] * self.key[j];
            }
            equation[self.dim as usize] =
                modulus(answer + rng.random_range(neg_fuzz..max_fuzz), self.modulo);
        }

        Public::new(self.modulo, key, add, self.dim)
    }

    pub fn decrypt<'a>(&self, message: &'a [u8]) -> Result<String, CastError<&'a [u8], [i32]>> {
        let message: &[i32] = FromBytes::ref_from_bytes(message)?;
        let add = self.add as f32;

        Ok(message
            .par_chunks(self.key.len() + 1)
            .map(|message_chunk| {
                let chr_answer: i32 = self
                    .key
                    .iter()
                    .zip(message_chunk)
                    .map(|(num, chunklet)| num * chunklet)
                    .sum();

                // Chunk should have size otherwise would have failed earlier
                let last = message_chunk.last().unwrap_or_else(|| &0);
                from_u32((modulus(last - chr_answer, self.modulo) as f32 / add).round() as u32)
                    .unwrap_or_else(|| '💩')
            })
            .collect())
    }
}

impl Display for Secret16 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let output = format!("Secret {{ {:?} }}", self.key)
            .replace("[", "")
            .replace("]", "");

        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decryption() {
        let secret = Secret16::new();
        let public = secret.generate_public_key();

        let message = "Hello World".to_string();

        let encrypted = public.encrypt(&message);
        let decrypted = secret.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decryption_utf8() {
        let secret = Secret16::new();
        let public = secret.generate_public_key();

        let message = "こんにちは世界".to_string();

        let encrypted = public.encrypt(&message);
        let decrypted = secret.decrypt(&encrypted).unwrap();

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
