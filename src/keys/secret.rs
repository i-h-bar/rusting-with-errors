use std::char::from_u32;
use std::fmt::{Display, Formatter};

use rand::{Rng, rngs::OsRng};
use rayon::prelude::*;

use crate::keys::{MAX_CHR, modulus};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Secret {
    pub(crate) key: Vec<i64>,
    pub(crate) modulo: i64,
    pub(crate) add: i64,
}


impl Secret {
    pub fn new(dim: usize) -> Self {
        let mut rng: OsRng = OsRng::default();
        let mut key: Vec<i64> = vec![0; dim];
        let modulo = rng.gen_range(111206400..1112064000);
        let add: i64 = modulo / MAX_CHR;
        for i in 0..dim {
            key[i] = rng.gen_range(-32768..32768);
        }

        Secret { key, modulo, add }
    }

    pub fn decrypt(&self, message: &Vec<i64>) -> String {
        let mut decrypted = String::new();
        let dim = self.key.len() + 1;
        let len = message.len() / dim;
        let mut answers: Vec<f64> = vec![0.0; len];

        answers.par_iter_mut().enumerate().for_each(|(i, expected)|
            {
                let mut chr_answer: i64 = 0;
                for j in 0..self.key.len() {
                    chr_answer += self.key[j] * message[(i * dim) + j];
                }

                let answer = (
                    modulus(message[(i * dim) + dim - 1] - chr_answer, self.modulo) as f64 / self.add as f64
                ).round();
                *expected = answer;
            }
        );

        for answer in &answers {
            decrypted.push(from_u32(*answer as u32).unwrap_or_else(|| '💩'));
        }

        decrypted
    }
}


impl Display for Secret {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if self.key.len() > 10 {
            let key = &self.key[..10];
            let output = format!("Secret {{ {:?}... }}", key)
                .replace("[", "").replace("]", "");

            write!(f, "{}", output)
        } else {
            let output = format!("Secret {{ {:?} }}", self.key)
                .replace("[", "").replace("]", "");

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