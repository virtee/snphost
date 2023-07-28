// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

pub const SNPHOST: &'static str = env!("CARGO_BIN_EXE_snphost");

pub fn run(arglist: &[&str]) -> String {
    let output = Command::new(SNPHOST).args(arglist).output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    if !output.status.success() {
        panic!(
            "\n{} command failed.\narglist={:?}\nstdout={}\nstderr={}\n",
            arglist[0], arglist, stdout, stderr
        );
    }

    stdout
}
