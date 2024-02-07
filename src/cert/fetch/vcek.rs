// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{create_dir_all, OpenOptions},
    io::Write,
    path::PathBuf,
};

use crate::{firmware, platform_status, processor::ProcessorGeneration};

use anyhow::{Context, Result};
use curl::easy::Easy;
use sev::certs::snp::Certificate;
use structopt::StructOpt;

use super::super::EncodingFormat;

#[derive(StructOpt)]
pub struct Vcek {
    #[structopt(about = "The format in which to encode the certificate")]
    encoding_fmt: EncodingFormat,

    #[structopt(about = "The path of a directory to store the encoded VCEK in")]
    path: PathBuf,
}

pub fn cmd(vcek: Vcek) -> Result<()> {
    let url = vcek_url()?;
    let cert = fetch(&url).context(format!("unable to fetch VCEK from {}", url))?;

    let (vcek_name, vcek_bytes) = match vcek.encoding_fmt {
        EncodingFormat::Der => ("vcek.der", cert.to_der()?),
        EncodingFormat::Pem => ("vcek.pem", cert.to_pem()?),
    };

    // Create Directory if not exists first, then write the files.
    if !vcek.path.exists() {
        create_dir_all(&vcek.path)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(vcek.path.join(vcek_name))?;

    file.write_all(&vcek_bytes)?;

    Ok(())
}

pub fn fetch(url: &str) -> Result<Certificate> {
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

    Ok(Certificate::from_der(buf.as_slice())?)
}

pub fn vcek_url() -> Result<String> {
    let id = firmware()?
        .get_identifier()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("error fetching identifier")?;
    let status = platform_status()?;
    let gen = ProcessorGeneration::current()?.to_kds_url();

    Ok(format!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                         gen, id, status.reported_tcb_version.bootloader,
                         status.reported_tcb_version.tee,
                         status.reported_tcb_version.snp,
                         status.reported_tcb_version.microcode))
}
