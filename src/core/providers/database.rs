/**
 * @author Harmoniq Punk
 * @year 2022
 * @license MPL-2.0
 */

pub mod database {
    #[cfg(feature = "fdb")]
    pub mod FoundationDB {}
}
