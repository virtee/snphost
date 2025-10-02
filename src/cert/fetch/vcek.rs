// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{
    fs::{create_dir_all, OpenOptions},
    io::Write,
    path::PathBuf,
};

use crate::{firmware, processor::ProcessorGeneration, snp_platform_status};

use anyhow::{Context, Result};
use curl::easy::Easy;
use sev::certs::snp::Certificate;

#[derive(Parser)]
pub struct Vcek {
    /// The format in which to encode the certificate
    #[arg(value_name = "encoding", required = true)]
    encoding_fmt: EncodingFormat,

    /// The path of a directory to store the encoded VCEK in
    #[arg(value_name = "path", required = true)]
    path: PathBuf,

    /// The URL of the VCEK. If not explicitly set, the URL will be generated based on firmware data
    #[arg(value_name = "url", required = false)]
    url: Option<String>,
}

pub fn cmd(vcek: Vcek) -> Result<()> {
    let url = match vcek.url {
        Some(url) => url,
        None => vcek_url()?,
    };
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
    let status = snp_platform_status()?;
    let processor_generation = ProcessorGeneration::current()?;
    let vcek_endpoint = format!(
        "https://kdsintf.amd.com/vcek/v1/{}/{}",
        processor_generation.to_kds_url(),
        id
    );
    let parameters = format!(
        "blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        status.reported_tcb_version.bootloader,
        status.reported_tcb_version.tee,
        status.reported_tcb_version.snp,
        status.reported_tcb_version.microcode
    );

    match processor_generation {
        ProcessorGeneration::Turin => {
            if let Some(fmc) = status.reported_tcb_version.fmc {
                Ok(format!(
                    "{}?fmcSPL={:02}&{}",
                    vcek_endpoint, fmc, parameters
                ))
            } else {
                Err(anyhow!(
                    "Unable to retrieve FMC value from this Turin generation processor"
                ))
            }
        }
        _ => Ok(format!("{}?{}", vcek_endpoint, parameters)),
    }
}
