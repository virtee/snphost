// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::{arg, command, CommandFactory, Parser, Subcommand, ValueEnum};

mod cert;
use cert::{export, fetch, import, verify};
use sev::firmware::host::*;
mod cli;
mod config;
mod ok;
mod processor;
mod show;

use cli::SnpHost;
use std::path::PathBuf;

fn generate_man_pages() -> std::io::Result<()> {
    clap_mangen::generate_to(
        SnpHost::command(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/"),
    )
}

fn main() -> std::io::Result<()> {
    // Uses clap_mangen to generate all relevant man pages.
    generate_man_pages()
}
