// SPDX-License-Identifier: Apache-2.0

use std::{fs::read_to_string, path::PathBuf};

use serial_test::serial;

mod util;

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[test]
#[serial]
fn import_ok() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/testdata/import");

    util::run(&["import", path.to_str().unwrap()]);
}

#[cfg_attr(not(all(has_sev, feature = "dangerous_hw_tests")), ignore)]
#[test]
#[serial]
fn export_ok() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/testdata/export");

    util::run(&["export", "pem", path.to_str().unwrap()]);

    let mut import_path = path.clone();
    import_path.pop();
    import_path.push("import");

    let (ex_ark, ex_ask) = files(&path);
    let (im_ark, im_ask) = files(&import_path);

    if im_ark != ex_ark {
        panic!("import and export ARK are different");
    }

    if im_ask != ex_ask {
        panic!("import and export ASK are different");
    }
}

fn files(path: &PathBuf) -> (String, String) {
    let ark = read_to_string(format!("{}/ark.pem", path.display())).unwrap();
    let ask = read_to_string(format!("{}/ask.pem", path.display())).unwrap();

    (ark, ask)
}
