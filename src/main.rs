// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]
mod cli;
use anyhow::Context;
use clap::{arg, command, Parser, Subcommand, ValueEnum};
use cli::SnpHost;
use sev::firmware::host::*;

mod cert;
use cert::{export, fetch, import, verify};
mod config;
mod ok;
mod processor;
mod show;

use anyhow::Result;
fn main() -> Result<()> {
    env_logger::init();

    let snphost = SnpHost::parse();

    let result = snphost.cmd.handle(snphost.quiet);

    if !snphost.quiet {
        if let Err(ref e) = result {
            eprintln!("ERROR: {}", e);
        }
    }

    result
}
