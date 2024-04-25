// SPDX-License-Identifier: Apache-2.0

use super::*;

use sev::firmware::host::{CertTableEntry, CertType};
use std::{
    fs::{read, read_dir, DirEntry, File},
    io::Write,
    path::PathBuf,
};

use anyhow::{bail, Context, Result};

#[derive(Parser)]
pub struct Import {
    /// The directory where the certificates are stored
    #[arg(value_name = "dir-path", required = true)]
    pub dir_path: PathBuf,

    /// File where the formatted certificates will be stored.
    #[arg(value_name = "cert-file", required = true)]
    pub cert_file: PathBuf,
}

pub fn cmd(import: Import) -> Result<()> {
    if !import.dir_path.exists() {
        bail!(format!("path {} does not exist", import.dir_path.display()));
    }

    let mut table: Vec<CertTableEntry> = vec![];

    // For each cert in the directory convert into a kernel formatted cert and write into file
    for dir_entry in read_dir(import.dir_path.clone())? {
        match dir_entry {
            Ok(de) => table_add_entry(de, &mut table)?,
            Err(_) => {
                bail!(format!(
                    "unable to read directory at path {}",
                    import.dir_path.display()
                ))
            }
        }
    }

    let cert_bytes = CertTableEntry::cert_table_to_vec_bytes(&table)
        .context("Failed to convert certificates to GHCB bytes specification.")?;

    // Write cert into directory
    let mut file = if import.cert_file.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(import.cert_file)
            .context("Unable to overwrite kernel cert file contents")?
    } else {
        File::create(import.cert_file).context("Unable to create kernel cert file")?
    };

    file.write(&cert_bytes)
        .context(format!("unable to write data to file {:?}", file))?;

    Ok(())
}

fn table_add_entry(de: DirEntry, table: &mut Vec<CertTableEntry>) -> Result<()> {
    match entry_get_type(&de.path())? {
        Some(cert_type) => {
            let data = read(de.path())?;

            table.push(CertTableEntry::new(cert_type, data));

            Ok(())
        }
        None => Ok(()),
    }
}

fn entry_get_type(path: &PathBuf) -> Result<Option<CertType>> {
    let file_name_string = path
        .file_name()
        .context(format!("unable to read file at path {:?}", path))?
        .to_string_lossy()
        .into_owned();

    let subs: Vec<&str> = file_name_string.split('.').collect();
    match subs[0] {
        "ark" => Ok(Some(CertType::ARK)),
        "ask" => Ok(Some(CertType::ASK)),
        "vlek" => Ok(Some(CertType::VLEK)),
        "vcek" => Ok(Some(CertType::VCEK)),
        _ => Ok(None),
    }
}
