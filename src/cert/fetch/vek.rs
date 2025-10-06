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
pub struct Vek {
    /// The format in which to encode the certificate
    #[arg(value_name = "encoding", required = true)]
    encoding_fmt: EncodingFormat,

    /// The path of a directory to store the encoded VEK in
    #[arg(value_name = "path", required = true)]
    path: PathBuf,

    /// The URL of the VEK. If not explicitly set, the URL will be generated based on firmware data
    #[arg(value_name = "url", required = false)]
    url: Option<String>,
}

pub fn cmd(vek: Vek) -> Result<()> {
    let url = match vek.url {
        Some(url) => url,
        None => vek_url(Endorsement::Vcek)?,
    };
    let cert = fetch(&url).context(format!("unable to fetch VCEK from {}", url))?;

    let (vek_name, vek_bytes) = match vek.encoding_fmt {
        EncodingFormat::Der => ("vcek.der", cert.to_der()?),
        EncodingFormat::Pem => ("vcek.pem", cert.to_pem()?),
    };

    // Create Directory if not exists first, then write the files.
    if !vek.path.exists() {
        create_dir_all(&vek.path)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(vek.path.join(vek_name))?;

    file.write_all(&vek_bytes)?;

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

pub fn vek_url(endorser: Endorsement) -> Result<String> {
    let id = firmware()?
        .get_identifier()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("error fetching identifier")?;
    let status = snp_platform_status()?;
    let processor_generation = ProcessorGeneration::current()?;
    let vek_endpoint = if endorser == Endorsement::Vcek {
        format!(
            "https://kdsintf.amd.com/vcek/v1/{}/{}",
            processor_generation.to_kds_url(),
            id
        )
    } else {
        format!(
            "https://kdsintf.amd.com:444/vlek/v1/{}/cert",
            processor_generation.to_kds_url(),
        )
    };
    let parameters = format!(
        "blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        status.reported_tcb_version.bootloader,
        status.reported_tcb_version.tee,
        status.reported_tcb_version.snp,
        status.reported_tcb_version.microcode
    );

    match processor_generation {
        // Turin+ processors also require the FMC parameter to fetch VCEKs.
        ProcessorGeneration::Turin => {
            if let Some(fmc) = status.reported_tcb_version.fmc {
                Ok(format!("{}?fmcSPL={:02}&{}", vek_endpoint, fmc, parameters))
            } else {
                Err(anyhow!(
                    "Unable to retrieve FMC value from this Turin generation processor"
                ))
            }
        }
        _ => Ok(format!("{}?{}", vek_endpoint, parameters)),
    }
}
