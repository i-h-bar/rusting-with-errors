pub mod keys;

use keys::secret::Secret16;

fn main() {
    let secret = Secret16::new();
    let public = secret.generate_public_key();

    let message = "Hello, World!";
    let encrypted = public.encrypt(message);

    // println!("{:?}", encrypted);

    let decrypted = secret.decrypt(&encrypted).unwrap();

    println!("{}", decrypted);
}
