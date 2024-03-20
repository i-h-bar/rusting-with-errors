pub mod secret;
pub mod public;

const MAX_CHR: i64 = 1114111;


fn modulus(num: i64, modulo: i64) -> i64 {
    if num > 0 {
        num % modulo
    } else {
        ((num % modulo) + modulo) % modulo
    }
}