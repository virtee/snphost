// SPDX-License-Identifier: Apache-2.0

use super::*;
use anyhow::{Context, Result};
use curl::easy::Easy;
use sev::certs::snp::{ca::Chain, Certificate};
use std::{
    fs::{create_dir_all, OpenOptions},
    io::Write,
    path::PathBuf,
};

use super::super::EncodingFormat;
use crate::processor::ProcessorGeneration;

#[derive(Parser)]
pub struct Ca {
    /// The format the certs are encoded in.
    #[arg(value_name = "encoding", required = true)]
    pub encoding_fmt: EncodingFormat,

    /// The directory to write the certificates to
    #[arg(value_name = "dir-path", required = true)]
    pub dir_path: PathBuf,
}

fn write_cert(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)
        .context("Failed to write certificate!")
}

pub fn cmd(ca: Ca) -> Result<()> {
    let url: String = ca_chain_url()?;
    let cert_chain: Chain = fetch(&url)?;

    let ((ask_path, ask_bytes), (ark_path, ark_bytes)) = match ca.encoding_fmt {
        EncodingFormat::Der => (
            ("ask.der", cert_chain.ask.to_der()?),
            ("ark.der", cert_chain.ark.to_der()?),
        ),
        EncodingFormat::Pem => (
            ("ask.pem", cert_chain.ask.to_pem()?),
            ("ark.pem", cert_chain.ark.to_pem()?),
        ),
    };

    // Create Directory if not exists first, then write the files.
    if !ca.dir_path.exists() {
        create_dir_all(&ca.dir_path)?;
    }

    write_cert(&ca.dir_path.join(ask_path), &ask_bytes)?;
    write_cert(&ca.dir_path.join(ark_path), &ark_bytes)?;

    Ok(())
}

pub fn fetch(url: &str) -> Result<Chain> {
    let mut handle = Easy::new();
    let mut buf: Vec<u8> = Vec::new();

    handle.url(url)?;
    handle.get(true)?;

    let mut transfer = handle.transfer();
    transfer.write_function(|data| {
        buf.extend_from_slice(data);
        Ok(data.len())
    })?;

    transfer.perform()?;
    drop(transfer);

    Ok(Chain {
        ask: Certificate::from_pem(&buf[..2325])?,
        ark: Certificate::from_pem(&buf[2325..])?,
    })
}

fn ca_chain_url() -> Result<String> {
    Ok(format!(
        "https://kdsintf.amd.com/vcek/v1/{}/cert_chain",
        ProcessorGeneration::current()?.to_kds_url()
    ))
}
