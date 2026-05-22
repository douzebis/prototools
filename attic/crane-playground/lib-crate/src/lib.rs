pub fn hello() -> &'static str {
    "hello"
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hello() {
        assert_eq!(super::hello(), "hello");
    }
}
