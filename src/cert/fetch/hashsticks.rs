// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{
    collections::HashMap,
    fs::{create_dir_all, read_to_string, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use crate::{firmware, processor::ProcessorGeneration, snp_platform_status};

use anyhow::{Context, Result};
use curl::easy::{Easy, List};
use hex::decode;
use serde::Deserialize;

#[derive(Parser)]
pub struct Hashsticks {
    /// The path of a directory to store the encoded VEK in
    #[arg(value_name = "path", required = true)]
    pub path: PathBuf,

    /// The path of the client certificate
    #[arg(value_name = "client-cert", required = true)]
    pub client_cert: PathBuf,

    /// The path of the client private key
    #[arg(value_name = "private-key", required = true)]
    pub private_key: PathBuf,

    /// The hwid of the requested hash stick
    #[arg(long, value_name = "hwid", conflicts_with = "json")]
    pub hwid: Option<String>,

    /// The path of the request file to request hashsticks for multiple machines.
    #[arg(long, value_name = "json", conflicts_with = "hwid")]
    pub json: Option<PathBuf>,
}

// Define a struct to deserialize the JSON response
#[derive(Deserialize, Debug)]
struct KDSResponse {
    results: Vec<HashMap<String, String>>,
}

pub fn cmd(hashsticks: Hashsticks) -> Result<()> {
    let url = vlek_hashsticks_url()?;
    let request_body: String;
    let mut preprocess = false;
    let hashsticks_filename = "hashsticks";

    if let Some(body) = hashsticks.json {
        request_body = read_to_string(&body)?;
    } else if let Some(hwid) = hashsticks.hwid {
        (preprocess, request_body) = (true, format!("{{\"hwids\":[\"{}\"]}}", hwid));
    } else {
        let hwid = firmware()?
            .get_identifier()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("error detecting identifier on this machine")?;
        (preprocess, request_body) = (true, format!("{{\"hwids\":[\"{}\"]}}", hwid));
    }

    let cert = fetch(
        &hashsticks.client_cert,
        &hashsticks.private_key,
        &url,
        &request_body,
    )
    .context(format!("unable to fetch VLEK hashsticks from {}", url))?;

    let mut hashsticks_bytes: Vec<u8> = Vec::new();
    if preprocess {
        let data = serde_json::from_str::<KDSResponse>(cert.as_str())?;
        if let Some(results) = data.results.first() {
            for (hwid, hashstick) in results {
                if hashstick != "not found" {
                    hashsticks_bytes = decode(hashstick)?;
                } else {
                    eprintln!("{}: {}", hwid, hashstick);
                    return Ok(());
                }
            }
        } else {
            eprintln!("malformatted response from KDS");
            return Ok(());
        }
    } else {
        hashsticks_bytes = cert.into_bytes()
    }

    // Create Directory if not exists first, then write the files.
    if !hashsticks.path.exists() {
        create_dir_all(&hashsticks.path)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(hashsticks.path.join(hashsticks_filename))?;

    file.write_all(&hashsticks_bytes)?;

    Ok(())
}

pub fn fetch(cert: &PathBuf, key: &PathBuf, url: &str, body: &str) -> Result<String> {
    let mut handle = Easy::new();
    let mut buf: Vec<u8> = Vec::new();

    handle.ssl_cert(cert)?;
    handle.ssl_key(key)?;
    handle.url(url)?;
    handle.post(true)?;

    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;

    handle.post_field_size(body.len() as u64)?;

    let mut transfer = handle.transfer();
    transfer.read_function(|data| Ok(body.as_bytes().read(data).unwrap_or(0)))?;
    transfer.write_function(|data| {
        buf.extend_from_slice(data);
        Ok(data.len())
    })?;

    transfer.perform()?;
    drop(transfer);

    let response_code = handle.response_code()?;
    let response_body = String::from_utf8(buf)?;
    if response_code == 200 {
        Ok(response_body)
    } else {
        Err(anyhow!(response_body))
    }
}

pub fn vlek_hashsticks_url() -> Result<String> {
    let status = snp_platform_status()?;
    let processor_generation = ProcessorGeneration::current()?;
    let hashsticks_endpoint = format!(
        "https://kdsintf.amd.com:444/vlek/v1/{}/hash_sticks",
        processor_generation.to_kds_url(),
    );
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
                Ok(format!(
                    "{}?fmcSPL={:02}&{}",
                    hashsticks_endpoint, fmc, parameters
                ))
            } else {
                Err(anyhow!(
                    "Unable to retrieve FMC value from this Turin generation processor"
                ))
            }
        }
        _ => Ok(format!("{}?{}", hashsticks_endpoint, parameters)),
    }
}
