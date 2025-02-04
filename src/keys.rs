use zerocopy::{FromBytes, Immutable, IntoBytes};

pub mod public;
pub mod secret;


const MAX_CHR: i32 = 1114111;

fn modulus(num: i32, modulo: i32) -> i32 {
    ((num % modulo) + modulo) % modulo
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message() {
        let message = vec![1, 2, 3];
        let b = message.as_bytes();
        let c = std::str::from_utf8(b);
        println!("{:?}", c);
    }
}

