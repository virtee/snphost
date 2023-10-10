// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::fs::{read, DirEntry};

#[derive(StructOpt)]
pub struct Import {
    #[structopt(about = "The directory to find the encoded certificates")]
    pub path: PathBuf,
}

pub fn cmd(import: Import) -> Result<()> {
    if !import.path.exists() {
        bail!(format!("path {} does not exist", import.path.display()));
    }

    let mut table: Vec<CertTableEntry> = vec![];

    for dir_entry in fs::read_dir(import.path.clone())? {
        match dir_entry {
            Ok(de) => table_add_entry(de, &mut table)?,
            Err(_) => {
                bail!(format!(
                    "unable to read directory at path {}",
                    import.path.display()
                ))
            }
        }
    }

    firmware()?.snp_set_ext_config(ExtConfig::new_certs_only(table))?;

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
