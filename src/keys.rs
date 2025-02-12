use std::char::from_u32;
use std::fmt;
use std::fmt::Formatter;
use rayon::prelude::*;
use zerocopy::FromBytes;
use crate::keys::DecryptError::{ByteParseError, SliceAccessError, U32ParseError};

pub mod public;
pub mod secret;

const MAX_CHR: i32 = 1114111;

#[derive(Debug)]
pub enum DecryptError {
    ByteParseError,
    SliceAccessError,
    U32ParseError,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let message = match &self {
            ByteParseError => "byte parse error",
            SliceAccessError => "slice access error",
            U32ParseError => "u32 parse error",
        };

        write!(f, "{}", message)
    }
}

fn modulus(num: i32, modulo: i32) -> i32 {
    ((num % modulo) + modulo) % modulo
}

fn _decrypt(message: &[u8], key: &[i32], add: i32, modulo: i32) -> Result<String, DecryptError> {
    if message.is_empty() {
        return Ok(String::new());
    }

    let message: &[i32] = FromBytes::ref_from_bytes(message).map_err(|_| ByteParseError)?;
    let add = add as f32;

    Ok(message
        .par_chunks(key.len() + 1)
        .map(|message_chunk| {
            let chr_answer: i32 = key
                .iter()
                .zip(message_chunk)
                .map(|(num, chunklet)| num * chunklet)
                .sum();

            let last = message_chunk.last().ok_or_else(|| SliceAccessError)?;
            Ok(
                from_u32((modulus(last - chr_answer, modulo) as f32 / add).round() as u32)
                    .ok_or_else(|| U32ParseError)?,
            )
        })
        .collect::<Result<String, DecryptError>>()?)
}

