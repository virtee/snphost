// SPDX-License-Identifier: Apache-2.0

use sev::firmware::host::{CertTableEntry, CertType};
use std::{
    fs::{read, read_dir, DirEntry, File},
    io::Write,
    path::PathBuf,
};

use structopt::StructOpt;

use anyhow::{anyhow, bail, Context, Result};

#[derive(StructOpt)]
pub struct Import {
    #[structopt(about = "The directory where the certificates are stored")]
    pub cert_dir: PathBuf,

    #[structopt(about = "File where the formatted certificates will be stored.")]
    pub target_file: PathBuf,
}

pub fn cmd(import: Import) -> Result<()> {
    if !import.cert_dir.exists() {
        bail!(format!("path {} does not exist", import.cert_dir.display()));
    }

    let mut table: Vec<CertTableEntry> = vec![];

    // For each cert in the directory convert into a kernel formatted cert and write into file
    for dir_entry in read_dir(import.cert_dir.clone())? {
        match dir_entry {
            Ok(de) => table_add_entry(de, &mut table)?,
            Err(_) => {
                bail!(format!(
                    "unable to read directory at path {}",
                    import.cert_dir.display()
                ))
            }
        }
    }

    let cert_bytes = CertTableEntry::cert_table_to_vec_bytes(&table)
        .context("Failed to convert certificates to GHCB formatted bytes.")?;

    // Write cert into directory
    let mut file = if import.target_file.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(import.target_file)
            .context("Unable to overwrite kernel cert file contents")?
    } else {
        File::create(import.target_file).context("Unable to create kernel cert file")?
    };

    file.write(&cert_bytes)
        .context(format!("unable to write data to file {:?}", file))?;

    Ok(())
}

fn table_add_entry(de: DirEntry, table: &mut Vec<CertTableEntry>) -> Result<()> {
    let cert_type = entry_get_type(&de.path())?;
    let data = read(de.path())?;

    table.push(CertTableEntry::new(cert_type, data));

    Ok(())
}

fn entry_get_type(path: &PathBuf) -> Result<CertType> {
    let file_name_string = path
        .file_name()
        .context(format!("unable to read file at path {:?}", path))?
        .to_string_lossy()
        .into_owned();

    let subs: Vec<&str> = file_name_string.split('.').collect();
    match subs[0] {
        "ark" => Ok(CertType::ARK),
        "ask" => Ok(CertType::ASK),
        "vcek" => Ok(CertType::VCEK),
        _ => Err(anyhow!(
            "unable to determine certificate type of path {:?}",
            path
        )),
    }
}
