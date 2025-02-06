pub mod keys;

use keys::secret::Secret16;
use zerocopy::IntoBytes;

fn main() {
    let secret = Secret16::new();
    let public = secret.generate_public_key();

    let s_key = secret.as_bytes();
    let p_key = public.as_bytes();
    println!("Secret: {}", s_key.len());
    println!("Secret: {}", p_key.len());

    let message = "Hello World!".to_string();
    let encrypted = public.encrypt(&message);

    let decrypted = secret.decrypt(&encrypted);

    println!("{decrypted}")
}
