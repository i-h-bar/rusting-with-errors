pub mod keys;
use keys::{public::Public, secret::Secret};

fn main() {
    let secret = Secret::new(64);
    let public = Public::from(&secret);

    let message = "Hello World!".to_string();
    let encrypted = public.encrypt(&message);

    let decrypted = secret.decrypt(&encrypted);

    println!("{decrypted}")
}
