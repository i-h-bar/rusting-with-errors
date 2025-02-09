use std::fmt;
use std::fmt::Formatter;

pub mod public;
pub mod secret;


type DecryptResult<T> = Result<T, DecryptError>;

const MAX_CHR: i32 = 1114111;


#[derive(Debug, Clone)]
pub enum DecryptError {
    ByteParseError,
    VectorError
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let message = match &self {
            DecryptError::ByteParseError => "byte parse error",
            DecryptError::VectorError => "vector error",
        };

        write!(f, "{}", message)
    }
}

fn modulus(num: i32, modulo: i32) -> i32 {
    ((num % modulo) + modulo) % modulo
}
