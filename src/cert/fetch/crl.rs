// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::processor::ProcessorGeneration;
use anyhow::{Context, Result};
use curl::easy::Easy;
use std::{
    fs::{create_dir_all, OpenOptions},
    io::Write,
    path::PathBuf,
};

fn crl_url() -> Result<String> {
    Ok(format!(
        "https://kdsintf.amd.com/vcek/v1/{}/crl",
        ProcessorGeneration::current()?.to_kds_url()
    ))
}

#[derive(Parser)]
pub struct Crl {
    /// The directory to write the CRL to
    #[arg(value_name = "dir-path", required = true)]
    pub dir_path: PathBuf,
}

pub fn cmd(crl: Crl) -> Result<()> {
    let url: String = crl_url()?;
    let bytes: Vec<u8> = fetch(&url)?;

    // Create Directory if not exists first, then write the files.
    if !crl.dir_path.exists() {
        create_dir_all(&crl.dir_path)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(crl.dir_path.join(format!(
            "{}.crl",
            ProcessorGeneration::current()?.to_kds_url()
        )))?;

    file.write_all(&bytes)
        .context("Failed to write CRL to directory specified!")
}

pub fn fetch(url: &str) -> Result<Vec<u8>> {
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

    Ok(buf)
}
