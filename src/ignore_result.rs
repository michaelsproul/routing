/// Add an `.ignore()` method to `Result`.
pub trait Ignore: Sized {
    /// Ignore the given value (drop it).
    fn ignore(self) {}
}

impl <T, E> Ignore for Result<T, E> {}
