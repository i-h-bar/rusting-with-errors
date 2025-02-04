use std::char::from_u32;
use std::fmt::{Display, Formatter};
use zerocopy::FromBytes;

use rand::{rngs::OsRng, Rng};
use rayon::prelude::*;

use crate::keys::{modulus, MAX_CHR};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Secret {
    pub(crate) key: Vec<i32>,
    pub(crate) modulo: i32,
    pub(crate) add: i32,
}

impl Secret {
    pub fn new(dim: usize) -> Self {
        let mut rng = rand::rng();
        let mut key: Vec<i32> = vec![0; dim];
        let modulo = rng.random_range(111206400..1112064000);
        let add: i32 = modulo / MAX_CHR;
        for i in 0..dim {
            key[i] = rng.random_range(-4096..4096);
        }

        Secret { key, modulo, add }
    }

    pub fn decrypt(&self, message: &str) -> String {
        let message: &[i32] = FromBytes::ref_from_bytes(message.as_bytes()).unwrap();
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

                *expected = (
                    modulus(message[(i * dim) + dim - 1] - chr_answer, self.modulo) as f32
                            / self.add as f32
                )
                    .round() as u32;
            });

        for answer in answers {
            decrypted.push(from_u32(answer).unwrap_or_else(|| '💩'));
        }

        decrypted
    }
}

impl Display for Secret {
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
        let secret = Secret::new(64);
        let public = Public::from(&secret);

        let message = "Hello World".to_string();

        let encrypted = public.encrypt(&message);
        let decrypted = secret.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decryption_utf8() {
        let secret = Secret::new(64);
        let public = Public::from(&secret);

        let message = "こんにちは世界".to_string();

        let encrypted = public.encrypt(&message);
        let decrypted = secret.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn secret_creation() {
        let secret = Secret::new(64);
        assert_eq!(secret.key.len(), 64);

        let mod_range = 111206400..1112064000;
        assert!(mod_range.contains(&secret.modulo));

        let key_range = -32768..32768;
        for num in secret.key.iter() {
            assert!(key_range.contains(num));
        }
    }
}
