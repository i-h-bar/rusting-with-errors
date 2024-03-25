pub mod keys;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_secret_pub() {
        let _ = keys::secret::Secret::new(4);
    }

    #[test]
    fn test_public_pub() {
        let secret = keys::secret::Secret::new(64);
        let _ = keys::public::Public::from(&secret);
    }
}
