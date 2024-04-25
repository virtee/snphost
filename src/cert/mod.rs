// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) mod export;
pub(crate) mod fetch;
pub(crate) mod import;
pub(crate) mod verify;

use std::str::FromStr;

use anyhow::{anyhow, Error};

#[derive(ValueEnum, Copy, Clone)]
pub enum EncodingFormat {
    /// Certificates are encoded in DER format
    Der,

    /// Certificates are encoded in PEM format
    Pem,
}

impl std::fmt::Display for EncodingFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Der => "der",
                Self::Pem => "pem",
            }
        )
    }
}

impl FromStr for EncodingFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "der" => Ok(Self::Der),
            "pem" => Ok(Self::Pem),
            _ => Err(anyhow!("unrecognized certificate encoding format")),
        }
    }
}
