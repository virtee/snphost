// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{
    arch::x86_64,
    fmt,
    fs::{self, File},
    mem::{transmute, MaybeUninit},
    os::unix::io::AsRawFd,
    str::from_utf8,
};

use colorful::*;

use msru::{Accessor, Msr};

type TestFn = dyn Fn() -> TestResult;

// SEV generation-specific bitmasks.
const SEV_MASK: usize = 1;
const ES_MASK: usize = 1 << 1;
const SNP_MASK: usize = 1 << 2;

struct Test {
    name: &'static str,
    gen_mask: usize,
    run: Box<TestFn>,
    sub: Vec<Test>,
}

struct TestResult {
    name: String,
    stat: TestState,
    mesg: Option<String>,
}

#[derive(PartialEq, Eq)]
enum TestState {
    Pass,
    Skip,
    Fail,
}

enum SevGeneration {
    Sev,
    Es,
    Snp,
}

impl fmt::Display for TestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TestState::Pass => format!("{}", "PASS".green()),
            TestState::Skip => format!("{}", "SKIP".yellow()),
            TestState::Fail => format!("{}", "FAIL".red()),
        };

        write!(f, "{}", s)
    }
}

enum SnpStatusTest {
    Tcb,
    Rmp,
    Snp,
}

enum SevStatusTests {
    Sev,
    Firmware,
    Seves,
}

impl fmt::Display for SnpStatusTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SnpStatusTest::Tcb => "Comparing TCB values",
            SnpStatusTest::Rmp => "RMP INIT",
            SnpStatusTest::Snp => "SNP INIT",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for SevStatusTests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SevStatusTests::Sev => "SEV INIT",
            SevStatusTests::Firmware => "SEV Firmware Version",
            SevStatusTests::Seves => "SEV-ES INIT",
        };
        write!(f, "{}", s)
    }
}

fn collect_tests() -> Vec<Test> {
    let tests = vec![
        Test {
            name: "AMD CPU",
            gen_mask: SEV_MASK,
            run: Box::new(|| {
                let res = unsafe { x86_64::__cpuid(0x0000_0000) };
                let name: [u8; 12] = unsafe { transmute([res.ebx, res.edx, res.ecx]) };
                let name = from_utf8(&name[..]).unwrap_or("ERROR_FOUND");

                let stat = if name == "AuthenticAMD" {
                    TestState::Pass
                } else {
                    TestState::Fail
                };

                TestResult {
                    name: "AMD CPU".to_string(),
                    stat,
                    mesg: None,
                }
            }),
            sub: vec![
                Test {
                    name: "Microcode support",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let cpu_name = {
                            let mut bytestr = Vec::with_capacity(48);
                            for cpuid in 0x8000_0002_u32..=0x8000_0004_u32 {
                                let cpuid = unsafe { x86_64::__cpuid(cpuid) };
                                let mut bytes: Vec<u8> =
                                    [cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx]
                                        .iter()
                                        .flat_map(|r| r.to_le_bytes().to_vec())
                                        .collect();
                                bytestr.append(&mut bytes);
                            }
                            String::from_utf8(bytestr)
                                .unwrap_or_else(|_| "ERROR_FOUND".to_string())
                                .trim()
                                .to_string()
                        };

                        let stat = if cpu_name.to_uppercase().contains("EPYC") {
                            TestState::Pass
                        } else {
                            TestState::Fail
                        };

                        TestResult {
                            name: "Microcode support".to_string(),
                            stat,
                            mesg: None,
                        }
                    }),
                    sub: vec![],
                },
                Test {
                    name: "Secure Memory Encryption (SME)",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let stat = if (res.eax & 0x1) != 0 {
                            TestState::Pass
                        } else {
                            TestState::Fail
                        };

                        TestResult {
                            name: "Secure Memory Encryption (SME)".to_string(),
                            stat,
                            mesg: None,
                        }
                    }),
                    sub: vec![Test {
                        name: "SME",
                        gen_mask: SEV_MASK,
                        run: Box::new(sme_test),
                        sub: vec![],
                    }],
                },
                Test {
                    name: "Secure Encrypted Virtualization (SEV)",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let stat = if (res.eax & 0x1 << 1) != 0 {
                            TestState::Pass
                        } else {
                            TestState::Fail
                        };

                        TestResult {
                            name: "Secure Encrypted Virtualization (SEV)".to_string(),
                            stat,
                            mesg: None,
                        }
                    }),
                    sub: vec![
                        Test {
                            name: "Encrypted State (SEV-ES)",
                            gen_mask: ES_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                let stat = if (res.eax & 0x1 << 3) != 0 {
                                    TestState::Pass
                                } else {
                                    TestState::Fail
                                };

                                TestResult {
                                    name: "Encrypted State (SEV-ES)".to_string(),
                                    stat,
                                    mesg: None,
                                }
                            }),
                            sub: vec![Test {
                                name: "SEV-ES INIT",
                                gen_mask: ES_MASK,
                                run: Box::new(|| sev_ioctl(SevStatusTests::Seves)),
                                sub: vec![],
                            }],
                        },
                        Test {
                            name: "SEV INIT",
                            gen_mask: SNP_MASK,
                            run: Box::new(|| sev_ioctl(SevStatusTests::Sev)),
                            sub: vec![],
                        },
                        Test {
                            name: "Secure Nested Paging (SEV-SNP)",
                            gen_mask: SNP_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                let stat = if (res.eax & 0x1 << 4) != 0 {
                                    TestState::Pass
                                } else {
                                    TestState::Fail
                                };

                                TestResult {
                                    name: "Secure Nested Paging (SEV-SNP)".to_string(),
                                    stat,
                                    mesg: None,
                                }
                            }),
                            sub: vec![
                                Test {
                                    name: "VM Permission Levels",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(|| {
                                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                        let stat = if (res.eax & 0x1 << 5) != 0 {
                                            TestState::Pass
                                        } else {
                                            TestState::Fail
                                        };

                                        TestResult {
                                            name: "VM Permission Levels".to_string(),
                                            stat,
                                            mesg: None,
                                        }
                                    }),
                                    sub: vec![Test {
                                        name: "Number of VMPLs",
                                        gen_mask: SNP_MASK,
                                        run: Box::new(|| {
                                            let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                            let num_vmpls = (res.ebx & 0xF000) >> 12;

                                            TestResult {
                                                name: "Number of VMPLs".to_string(),
                                                stat: TestState::Pass,
                                                mesg: Some(format!("{}", num_vmpls)),
                                            }
                                        }),
                                        sub: vec![],
                                    }],
                                },
                                Test {
                                    name: "SEV-SNP",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(snp_test),
                                    sub: vec![],
                                },
                                Test {
                                    name: "SEV Firmware Version",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(|| sev_ioctl(SevStatusTests::Firmware)),
                                    sub: vec![],
                                },
                                Test {
                                    name: "SNP INIT",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(|| snp_ioctl(SnpStatusTest::Snp)),
                                    sub: vec![],
                                },
                            ],
                        },
                        Test {
                            name: "Physical address bit reduction",
                            gen_mask: SEV_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = (res.ebx & 0b1111_1100_0000) >> 6;

                                TestResult {
                                    name: "Physical address bit reduction".to_string(),
                                    stat: TestState::Pass,
                                    mesg: Some(format!("{}", field)),
                                }
                            }),
                            sub: vec![],
                        },
                        Test {
                            name: "C-bit location",
                            gen_mask: SEV_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = res.ebx & 0b11_1111;

                                TestResult {
                                    name: "C-bit location".to_string(),
                                    stat: TestState::Pass,
                                    mesg: Some(format!("{}", field)),
                                }
                            }),
                            sub: vec![],
                        },
                        Test {
                            name: "Number of encrypted guests supported simultaneously",
                            gen_mask: SEV_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = res.ecx;

                                TestResult {
                                    name: "Number of encrypted guests supported simultaneously"
                                        .to_string(),
                                    stat: TestState::Pass,
                                    mesg: Some(format!("{}", field)),
                                }
                            }),
                            sub: vec![],
                        },
                        Test {
                            name: "Minimum ASID value for SEV-enabled, SEV-ES disabled guest",
                            gen_mask: SEV_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };
                                let field = res.edx;

                                TestResult {
                                    name:
                                        "Minimum ASID value for SEV-enabled, SEV-ES disabled guest"
                                            .to_string(),
                                    stat: TestState::Pass,
                                    mesg: Some(format!("{}", field)),
                                }
                            }),
                            sub: vec![],
                        },
                        Test {
                            name: "/dev/sev readable",
                            gen_mask: SEV_MASK,
                            run: Box::new(dev_sev_r),
                            sub: vec![],
                        },
                        Test {
                            name: "/dev/sev writable",
                            gen_mask: SEV_MASK,
                            run: Box::new(dev_sev_w),
                            sub: vec![],
                        },
                    ],
                },
                Test {
                    name: "Page flush MSR",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let msr_flag = if (res.eax & 0x1 << 2) != 0 {
                            "ENABLED".green()
                        } else {
                            "DISABLED".yellow()
                        };

                        let name = format!("Page flush MSR: {}", msr_flag);

                        TestResult {
                            name,
                            /*
                             * Page flush MSR can be enabled/disabled.
                             * Therefore, if the flag is disabled, it doesn't
                             * necessarily mean that Page flush MSR *isn't*
                             * supported, but rather that it is supported yet
                             * currently disabled. So instead of returning
                             * TestState::Fail (indicating that Page flush MSR
                             * isn't supported), return TestState::Pass and
                             * indicate to the caller whether it is enabled or
                             * disabled.
                             */
                            stat: TestState::Pass,
                            mesg: None,
                        }
                    }),
                    sub: vec![],
                },
            ],
        },
        Test {
            name: "KVM Support",
            gen_mask: SEV_MASK,
            run: Box::new(has_kvm_support),
            sub: vec![
                Test {
                    name: "SEV enabled in KVM",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| sev_enabled_in_kvm(SevGeneration::Sev)),
                    sub: vec![],
                },
                Test {
                    name: "SEV-ES enabled in KVM",
                    gen_mask: ES_MASK,
                    run: Box::new(|| sev_enabled_in_kvm(SevGeneration::Es)),
                    sub: vec![],
                },
                Test {
                    name: "SEV-SNP enabled in KVM",
                    gen_mask: SNP_MASK,
                    run: Box::new(|| sev_enabled_in_kvm(SevGeneration::Snp)),
                    sub: vec![],
                },
            ],
        },
        Test {
            name: "memlock limit",
            gen_mask: SEV_MASK,
            run: Box::new(memlock_rlimit),
            sub: vec![],
        },
        Test {
            name: "Read RMP tables",
            gen_mask: SNP_MASK,
            run: Box::new(get_rmp_address),
            sub: vec![],
        },
        Test {
            name: "RMP INIT",
            gen_mask: SNP_MASK,
            run: Box::new(|| snp_ioctl(SnpStatusTest::Rmp)),
            sub: vec![],
        },
        Test {
            name: "Compare TCB values",
            gen_mask: SNP_MASK,
            run: Box::new(|| snp_ioctl(SnpStatusTest::Tcb)),
            sub: vec![],
        },
    ];

    tests
}

const INDENT: usize = 2;

pub fn cmd(quiet: bool) -> Result<()> {
    let tests = collect_tests();

    if run_test(&tests, 0, quiet, SEV_MASK | ES_MASK | SNP_MASK) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "One or more tests in sevctl-ok reported a failure"
        ))
    }
}

fn run_test(tests: &[Test], level: usize, quiet: bool, mask: usize) -> bool {
    let mut passed = true;

    for t in tests {
        // Skip tests that aren't included in the specified generation.
        if (t.gen_mask & mask) != t.gen_mask {
            test_gen_not_included(t, level, quiet);
            continue;
        }

        let res = (t.run)();
        emit_result(&res, level, quiet);
        match res.stat {
            TestState::Pass => {
                if !run_test(&t.sub, level + INDENT, quiet, mask) {
                    passed = false;
                }
            }
            TestState::Fail => {
                passed = false;
                emit_skip(&t.sub, level + INDENT, quiet);
            }
            // Skipped tests are marked as skip before recursing. They are just emitted and not actually processed.
            TestState::Skip => unreachable!(),
        }
    }

    passed
}

fn emit_result(res: &TestResult, level: usize, quiet: bool) {
    if !quiet {
        let msg = match &res.mesg {
            Some(m) => format!(": {}", m),
            None => "".to_string(),
        };
        println!(
            "[ {:^4} ] {:width$}- {}{}",
            format!("{}", res.stat),
            "",
            res.name,
            msg,
            width = level
        )
    }
}

fn test_gen_not_included(test: &Test, level: usize, quiet: bool) {
    if !quiet {
        let tr_skip = TestResult {
            name: test.name.to_string(),
            stat: TestState::Skip,
            mesg: None,
        };

        println!(
            "[ {:^4} ] {:width$}- {}",
            format!("{}", tr_skip.stat),
            "",
            tr_skip.name,
            width = level
        );
        emit_skip(&test.sub, level + INDENT, quiet);
    }
}

fn emit_skip(tests: &[Test], level: usize, quiet: bool) {
    if !quiet {
        for t in tests {
            let tr_skip = TestResult {
                name: t.name.to_string(),
                stat: TestState::Skip,
                mesg: None,
            };

            println!(
                "[ {:^4} ] {:width$}- {}",
                format!("{}", tr_skip.stat),
                "",
                tr_skip.name,
                width = level
            );
            emit_skip(&t.sub, level + INDENT, quiet);
        }
    }
}

fn dev_sev_r() -> TestResult {
    let (stat, mesg) = match dev_sev_rw(fs::OpenOptions::new().read(true)) {
        Ok(_) => (TestState::Pass, "/dev/sev readable".to_string()),
        Err(e) => (TestState::Fail, format!("/dev/sev not readable: {}", e)),
    };

    TestResult {
        name: "Reading /dev/sev".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn dev_sev_w() -> TestResult {
    let (stat, mesg) = match dev_sev_rw(fs::OpenOptions::new().write(true)) {
        Ok(_) => (TestState::Pass, "/dev/sev writable".to_string()),
        Err(e) => (TestState::Fail, format!("/dev/sev not writable: {}", e)),
    };

    TestResult {
        name: "Writing /dev/sev".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn dev_sev_rw(file: &fs::OpenOptions) -> Result<()> {
    let path = "/dev/sev";

    match file.open(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::Error::new(Box::new(e))),
    }
}

fn has_kvm_support() -> TestResult {
    let path = "/dev/kvm";

    let (stat, mesg) = match File::open(path) {
        Ok(kvm) => {
            let api_version = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xAE00, 0) };
            if api_version < 0 {
                (
                    TestState::Fail,
                    "Error - accessing KVM device node failed".to_string(),
                )
            } else {
                (TestState::Pass, format!("API version: {}", api_version))
            }
        }
        Err(e) => (TestState::Fail, format!("Error reading {}: ({})", path, e)),
    };

    TestResult {
        name: "KVM supported".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn sev_enabled_in_kvm(gen: SevGeneration) -> TestResult {
    let path_loc = match gen {
        SevGeneration::Sev => "/sys/module/kvm_amd/parameters/sev",
        SevGeneration::Es => "/sys/module/kvm_amd/parameters/sev_es",
        SevGeneration::Snp => "/sys/module/kvm_amd/parameters/sev_snp",
    };
    let path = std::path::Path::new(path_loc);

    let (stat, mesg) = if path.exists() {
        match std::fs::read_to_string(path_loc) {
            Ok(result) => {
                if result.trim() == "1" || result.trim() == "Y" {
                    (TestState::Pass, "enabled".to_string())
                } else {
                    (
                        TestState::Fail,
                        format!("Error - contents read from {}: {}", path_loc, result.trim()),
                    )
                }
            }
            Err(e) => (
                TestState::Fail,
                format!("Error - (unable to read {}): {}", path_loc, e,),
            ),
        }
    } else {
        (
            TestState::Fail,
            format!("Error - {} does not exist", path_loc),
        )
    };

    TestResult {
        name: match gen {
            SevGeneration::Sev => "SEV enabled in KVM",
            SevGeneration::Es => "SEV-ES enabled in KVM",
            SevGeneration::Snp => "SEV-SNP enabled in KVM",
        }
        .to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn memlock_rlimit() -> TestResult {
    let mut rlimit = MaybeUninit::uninit();
    let res = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, rlimit.as_mut_ptr()) };

    let (stat, mesg) = if res == 0 {
        let r = unsafe { rlimit.assume_init() };

        (
            TestState::Pass,
            format!("Soft: {} | Hard: {}", r.rlim_cur, r.rlim_max),
        )
    } else {
        (
            TestState::Fail,
            "Unable to retrieve memlock resource limits".to_string(),
        )
    };

    TestResult {
        name: "Memlock resource limit".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

fn msr_bit_read(reg: u32, cpu: u16) -> Result<u64, anyhow::Error> {
    let mut msr = Msr::new(reg, cpu).context("Error Reading MSR")?;
    let raw_value = msr.read()?;
    Ok(raw_value)
}

fn sme_test() -> TestResult {
    let raw_value = match msr_bit_read(0xC0010010, 0) {
        Ok(raw) => raw,
        Err(e) => {
            return TestResult {
                name: "SME".to_string(),
                stat: TestState::Fail,
                mesg: format!("MSR read failed: {}", e).into(),
            }
        }
    };
    let (testres, mesg) = match raw_value >> 23 & 1 {
        1 => (TestState::Pass, "Enabled in MSR"),
        0 => (TestState::Fail, "Disabled in MSR"),
        _ => unreachable!(),
    };
    TestResult {
        name: "SME".to_string(),
        stat: testres,
        mesg: Some(mesg.to_string()),
    }
}

fn snp_test() -> TestResult {
    let raw_value = match msr_bit_read(0xC0010010, 0) {
        Ok(raw) => raw,
        Err(e) => {
            return TestResult {
                name: "SNP".to_string(),
                stat: TestState::Fail,
                mesg: format!("MSR read failed: {}", e).into(),
            }
        }
    };
    let (testres, mesg) = match raw_value >> 24 & 1 {
        1 => (TestState::Pass, "Enabled in MSR"),
        0 => (TestState::Fail, "Disabled in MSR"),
        _ => unreachable!(),
    };
    TestResult {
        name: "SNP".to_string(),
        stat: testres,
        mesg: Some(mesg.to_string()),
    }
}

fn get_rmp_address() -> TestResult {
    let rmp_base = match msr_bit_read(0xC0010132, 0) {
        Ok(raw) => raw,
        Err(e) => {
            return TestResult {
                name: "Reading RMP table".to_string(),
                stat: TestState::Fail,
                mesg: format!("Failed to read the desired MSR: {}", e).into(),
            }
        }
    };
    let rmp_end = match msr_bit_read(0xC0010133, 0) {
        Ok(raw) => raw,
        Err(e) => {
            return TestResult {
                name: "Reading RMP table".to_string(),
                stat: TestState::Fail,
                mesg: format!("Failed to read the desired MSR: {}", e).into(),
            }
        }
    };
    if rmp_base == 0 || rmp_end == 0 {
        TestResult {
            name: "Reading RMP table".to_string(),
            stat: TestState::Fail,
            mesg: Some("RMP table was not read successfully".into()),
        }
    } else {
        TestResult {
            name: "RMP table addresses".to_string(),
            stat: TestState::Pass,
            mesg: format!("Addresses: {} - {}", rmp_base, rmp_end).into(),
        }
    }
}

fn snp_ioctl(test: SnpStatusTest) -> TestResult {
    let status = match snp_platform_status() {
        Ok(stat) => stat,
        Err(e) => {
            return TestResult {
                name: test.to_string(),
                stat: TestState::Fail,
                mesg: Some(format!("Failed to get SNP Platform status {e}")),
            }
        }
    };

    match test {
        SnpStatusTest::Tcb => {
            if status.platform_tcb_version == status.reported_tcb_version {
                TestResult{
                            name: format!("{}", SnpStatusTest::Tcb),
                            stat: TestState::Pass,
                            mesg: format!("TCB versions match \n\n Platform TCB version: {} \n Reported TCB version: {}", 
                                        status.platform_tcb_version, status.reported_tcb_version).into()
                        }
            } else {
                TestResult {
                    name: format!("{}", SnpStatusTest::Tcb),
                    stat: TestState::Fail,
                    mesg: format!("The TCB versions did NOT match \n\n Platform TCB version: {} \n Reported TCB version: {}", 
                                    status.platform_tcb_version, status.reported_tcb_version).into(),
                }
            }
        }
        SnpStatusTest::Rmp => {
            if status.is_rmp_init == 1 {
                TestResult {
                    name: format!("{}", SnpStatusTest::Rmp),
                    stat: TestState::Pass,
                    mesg: Some("RMP is INIT".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", SnpStatusTest::Rmp),
                    stat: TestState::Fail,
                    mesg: Some("RMP is UNINIT".to_string()),
                }
            }
        }
        SnpStatusTest::Snp => {
            if status.state == 1 {
                TestResult {
                    name: format!("{}", SnpStatusTest::Snp),
                    stat: TestState::Pass,
                    mesg: Some("SNP is INIT".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", SnpStatusTest::Snp),
                    stat: TestState::Fail,
                    mesg: Some("SNP is UNINIT".to_string()),
                }
            }
        }
    }
}

fn sev_ioctl(test: SevStatusTests) -> TestResult {
    let status = match sev_platform_status() {
        Ok(stat) => stat,
        Err(e) => {
            return TestResult {
                name: test.to_string(),
                stat: TestState::Fail,
                mesg: Some(format!("Failed to get SEV Platform Status {e}")),
            }
        }
    };
    match test {
        SevStatusTests::Sev => {
            if status.state == State::Working {
                TestResult {
                    name: format!("{}", SevStatusTests::Sev),
                    stat: TestState::Pass,
                    mesg: Some("SEV is INIT and currently running a guest".to_string()),
                }
            } else if status.state == State::Initialized {
                TestResult {
                    name: format!("{}", SevStatusTests::Sev),
                    stat: TestState::Pass,
                    mesg: Some("SEV is INIT, but not currently running a guest".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", SevStatusTests::Sev),
                    stat: TestState::Fail,
                    mesg: Some("SEV is UNINIT".to_string()),
                }
            }
        }

        SevStatusTests::Firmware => {
            if status.build.version == 0.into() {
                TestResult {
                    name: format!("{}", SevStatusTests::Firmware),
                    stat: TestState::Fail,
                    mesg: Some(format!(
                        "Invalid Firmware version: {}",
                        status.build.version
                    )),
                }
            } else if status.build.version.minor < 51 {
                TestResult {
                    name: format!("{}", SevStatusTests::Firmware),
                    stat: TestState::Fail,
                    mesg: format!(
                        "SEV firmware version needs to be at least 1.51, 
                            current firmware version: {}",
                        status.build.version
                    )
                    .into(),
                }
            } else {
                TestResult {
                    name: format!("{}", SevStatusTests::Firmware),
                    stat: TestState::Pass,
                    mesg: format!("Sev firmware version: {}", status.build.version).into(),
                }
            }
        }

        SevStatusTests::Seves => {
            let (res, mesg) = match status.flags.bits() >> 8 & 1 {
                1 => (TestState::Pass, "Enabled"),
                0 => (TestState::Fail, "Disabled"),
                _ => unreachable!(),
            };
            TestResult {
                name: format!("{}", SevStatusTests::Seves),
                stat: res,
                mesg: Some(mesg.to_string()),
            }
        }
    }
}
