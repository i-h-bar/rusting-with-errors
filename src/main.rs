pub mod keys;
use keys::{public::Public, secret::Secret};

fn main() {
    let secret = Secret::new(4);
    let mut public = Public::from(&secret);

    let message = "Hello world!".to_string();
    let encrypted = public.encrypt(&message);

    let decrypted = secret.decrypt(&encrypted);

    println!("{decrypted:?}")
}