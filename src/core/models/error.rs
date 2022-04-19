/**
 * @author Harmoniq Punk
 * @year 2022
 * @license MPL-2.0
 */

use serde::Serialize;

pub mod error {

    use super::*;

    #[derive(Serialize)]
        pub struct Target {
            pub desc: String,
        }

}