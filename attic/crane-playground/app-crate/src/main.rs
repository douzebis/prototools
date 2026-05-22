fn main() {
    println!("{}", lib_crate::hello());
    #[cfg(feature = "extra")]
    println!("extra feature enabled");
}
