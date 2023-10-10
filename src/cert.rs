// SPDX-License-Identifier: Apache-2.0

use std::{result, str::FromStr};

use structopt::StructOpt;

use anyhow::anyhow;

#[derive(StructOpt, PartialEq, Eq)]
pub enum CertEncodingFormat {
    #[structopt(about = "Certificates are encoded in DER format")]
    Der,

    #[structopt(about = "Certificates are encoded in PEM format")]
    Pem,
}

impl ToString for CertEncodingFormat {
    fn to_string(&self) -> String {
        match self {
            Self::Der => "der".to_string(),
            Self::Pem => "pem".to_string(),
        }
    }
}

impl FromStr for CertEncodingFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        match s {
            "der" => Ok(Self::Der),
            "pem" => Ok(Self::Pem),
            _ => Err(anyhow!("unrecognized certificate encoding format")),
        }
    }
}
