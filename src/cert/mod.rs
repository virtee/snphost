// SPDX-License-Identifier: Apache-2.0

pub(crate) mod export;
pub(crate) mod fetch;
pub(crate) mod import;
pub(crate) mod verify;

use std::str::FromStr;

use structopt::StructOpt;

use anyhow::{anyhow, Error};

#[derive(StructOpt)]
pub enum EncodingFormat {
    #[structopt(about = "Certificates are encoded in DER format")]
    Der,

    #[structopt(about = "Certificates are encoded in PEM format")]
    Pem,
}

impl ToString for EncodingFormat {
    fn to_string(&self) -> String {
        match self {
            Self::Der => "der".to_string(),
            Self::Pem => "pem".to_string(),
        }
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
