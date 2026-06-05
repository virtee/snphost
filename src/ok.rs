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

use clap::{Args, ValueEnum};
use colorful::*;
use serde::{Serialize, Serializer};

use msru::{Accessor, Msr};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verbosity {
    Default,
    Short,
    Verbose,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Default,
    Json,
}

#[derive(Args, Clone)]
pub struct Ok {
    /// Show only failures with summary counts
    #[arg(short, long)]
    short: bool,

    /// Show detailed test descriptions grouped by category with detected issues summary
    #[arg(short, long, conflicts_with = "short")]
    verbose: bool,

    /// Controls how test results are rendered
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Default)]
    output: OutputFormat,
}

impl Ok {
    fn verbosity(&self) -> Verbosity {
        if self.verbose {
            Verbosity::Verbose
        } else if self.short {
            Verbosity::Short
        } else {
            Verbosity::Default
        }
    }

    fn output_format(&self) -> OutputFormat {
        self.output
    }
}

/// Category for grouping tests in verbose output
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TestCategory {
    CpuSupport,
    CpuInfo,
    BiosConfigured,
    PlatformInitialized,
    KvmConfig,
    Compliance,
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestCategory::CpuSupport => write!(f, "CPU Support"),
            TestCategory::CpuInfo => write!(f, "CPU Info"),
            TestCategory::BiosConfigured => write!(f, "BIOS Configured"),
            TestCategory::PlatformInitialized => write!(f, "Platform Initialized"),
            TestCategory::KvmConfig => write!(f, "KVM Config"),
            TestCategory::Compliance => write!(f, "Compliance"),
        }
    }
}

/// Metadata for a test: category, description, and fix hint.
#[derive(Clone, Copy)]
struct TestMetadata {
    category: TestCategory,
    description: &'static str,
    fix_hint: &'static str,
}

const MSR_HINT: &str = "Load MSR kernel module: sudo modprobe msr";
const SUDO_HINT: &str = "Run with sudo: sudo snphost ok";

/// Returns the appropriate fix hint for a failed test, overriding
/// the metadata hint for access/module issues.
fn effective_hint(meta: &TestMetadata, message: &Option<String>) -> &'static str {
    if let Some(m) = message {
        if m.contains("MSR read failed") || m.contains("Failed to read the desired MSR") {
            return MSR_HINT;
        }
        if m.contains("unable to open /dev/sev") || m.contains("Permission denied") {
            return SUDO_HINT;
        }
    }
    meta.fix_hint
}

type TestFn = dyn Fn() -> TestResult;

// SEV generation-specific bitmasks.
const SEV_MASK: usize = 1;
const ES_MASK: usize = 1 << 1;
const SNP_MASK: usize = 1 << 2;

struct Test {
    name: &'static str,
    gen_mask: usize,
    run: Box<TestFn>,
    meta: TestMetadata,
    sub: Vec<Test>,
}

struct TestResult {
    name: String,
    stat: TestState,
    mesg: Option<String>,
}

struct TestResultNode {
    result: TestResult,
    meta: TestMetadata,
    sub: Vec<TestResultNode>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TestState {
    Pass,
    Skip,
    Fail,
}

impl Serialize for TestState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            TestState::Pass => "pass",
            TestState::Skip => "skip",
            TestState::Fail => "fail",
        };
        serializer.serialize_str(s)
    }
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
    AliasCheck,
    Snp,
}

enum SevStatusTests {
    Sev,
    Firmware,
    SevEs,
}

impl fmt::Display for SnpStatusTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SnpStatusTest::Tcb => "Comparing TCB values",
            SnpStatusTest::Rmp => "RMP table initialized",
            SnpStatusTest::AliasCheck => "Alias check",
            SnpStatusTest::Snp => "SNP initialized",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for SevStatusTests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SevStatusTests::Sev => "SEV initialized",
            SevStatusTests::Firmware => "SEV firmware version",
            SevStatusTests::SevEs => "SEV-ES initialized",
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
            meta: TestMetadata {
                category: TestCategory::CpuSupport,
                description: "Checks CPU vendor string via CPUID is \"AuthenticAMD\"",
                fix_hint: "Requires AMD processor",
            },
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
                    meta: TestMetadata {
                        category: TestCategory::CpuSupport,
                        description: "Verifies processor brand string contains \"EPYC\" (server-class CPU required)",
                        fix_hint: "Need EPYC server-class CPU",
                    },
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
                    meta: TestMetadata {
                        category: TestCategory::CpuSupport,
                        description: "Checks CPUID 0x8000001F EAX bit 0 for SME hardware support",
                        fix_hint: "Need EPYC 7001+",
                    },
                    sub: vec![Test {
                        name: "SME",
                        gen_mask: SEV_MASK,
                        run: Box::new(sme_test),
                        meta: TestMetadata {
                            category: TestCategory::BiosConfigured,
                            description: "Reads MSR 0xC0010010 (SYSCFG) bit 23 to verify SME enabled at system level",
                            fix_hint: "BIOS: CBS > CPU Common > SMEE. Run: sudo modprobe msr",
                        },
                        sub: vec![],
                    }],
                },
                Test {
                    name: "Secure Encrypted Virtualization (SEV)",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let stat = if (res.eax & (0x1 << 1)) != 0 {
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
                    meta: TestMetadata {
                        category: TestCategory::CpuSupport,
                        description: "Checks CPUID 0x8000001F EAX bit 1 for SEV hardware support",
                        fix_hint: "Need EPYC with SEV",
                    },
                    sub: vec![
                        Test {
                            name: "SEV Firmware Version",
                            gen_mask: SNP_MASK,
                            run: Box::new(|| sev_ioctl(SevStatusTests::Firmware)),
                            meta: TestMetadata {
                                category: TestCategory::BiosConfigured,
                                description: "Queries /dev/sev PLATFORM_STATUS for firmware version (requires >= 1.51 for SNP)",
                                fix_hint: "Run with sudo. For SNP support, update BIOS for firmware >= 1.51",
                            },
                            sub: vec![],
                        },
                        Test {
                            name: "Encrypted State (SEV-ES)",
                            gen_mask: ES_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                let stat = if (res.eax & (0x1 << 3)) != 0 {
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
                            meta: TestMetadata {
                                category: TestCategory::CpuSupport,
                                description: "Checks CPUID 0x8000001F EAX bit 3 for SEV-ES hardware support",
                                fix_hint: "Need EPYC 7002+",
                            },
                            sub: vec![Test {
                                name: "SEV-ES initialized",
                                gen_mask: ES_MASK,
                                run: Box::new(|| sev_ioctl(SevStatusTests::SevEs)),
                                meta: TestMetadata {
                                    category: TestCategory::PlatformInitialized,
                                    description: "Queries SEV platform status flags bit 8 for SEV-ES initialization",
                                    fix_hint: "Run with sudo. Run: sudo modprobe kvm_amd sev=1 sev-es=1",
                                },
                                sub: vec![],
                            }],
                        },
                        Test {
                            name: "SEV initialized",
                            gen_mask: SNP_MASK,
                            run: Box::new(|| sev_ioctl(SevStatusTests::Sev)),
                            meta: TestMetadata {
                                category: TestCategory::PlatformInitialized,
                                description: "Queries SEV platform status state field (must be Initialized or Working)",
                                fix_hint: "Run with sudo. Run: sudo modprobe kvm_amd sev=1",
                            },
                            sub: vec![],
                        },
                        Test {
                            name: "Secure Nested Paging (SEV-SNP)",
                            gen_mask: SNP_MASK,
                            run: Box::new(|| {
                                let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                let stat = if (res.eax & (0x1 << 4)) != 0 {
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
                            meta: TestMetadata {
                                category: TestCategory::CpuSupport,
                                description: "Checks CPUID 0x8000001F EAX bit 4 for SEV-SNP hardware support",
                                fix_hint: "Need EPYC 7003+",
                            },
                            sub: vec![
                                Test {
                                    name: "VM Permission Levels",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(|| {
                                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                                        let stat = if (res.eax & (0x1 << 5)) != 0 {
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
                                    meta: TestMetadata {
                                        category: TestCategory::CpuSupport,
                                        description: "Checks CPUID 0x8000001F EAX bit 5 for VMPL hardware support",
                                        fix_hint: "Update BIOS to latest version",
                                    },
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
                                        meta: TestMetadata {
                                            category: TestCategory::CpuInfo,
                                            description: "Reads CPUID 0x8000001F EBX bits 15:12 for VMPL count (expected: 4)",
                                            fix_hint: "Informational, no action needed",
                                        },
                                        sub: vec![],
                                    }],
                                },
                                Test {
                                    name: "SEV-SNP",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(snp_test),
                                    meta: TestMetadata {
                                        category: TestCategory::BiosConfigured,
                                        description: "Reads MSR 0xC0010010 (SYSCFG) bit 24 to verify SNP enabled at system level",
                                        fix_hint: "BIOS: CBS > CPU Common > SNP Memory Coverage. Run: sudo modprobe msr",
                                    },
                                    sub: vec![],
                                },
                                Test {
                                    name: "SNP initialized",
                                    gen_mask: SNP_MASK,
                                    run: Box::new(|| snp_ioctl(SnpStatusTest::Snp)),
                                    meta: TestMetadata {
                                        category: TestCategory::PlatformInitialized,
                                        description: "Queries SNP_PLATFORM_STATUS state field = 1 (INIT state)",
                                        fix_hint: "Run with sudo. Need kernel 6.11+. Run: sudo modprobe kvm_amd sev_snp=1. Update BIOS for firmware >= 1.51 and reboot.",
                                    },
                                    sub: vec![
                                        Test {
                                            name: "Read RMP tables",
                                            gen_mask: SNP_MASK,
                                            run: Box::new(get_rmp_address),
                                            meta: TestMetadata {
                                                category: TestCategory::BiosConfigured,
                                                description: "Reads MSRs 0xC0010132 and 0xC0010133 for RMP base/end addresses",
                                                fix_hint: "Enable SNP Memory Coverage in BIOS. Run: sudo modprobe msr",
                                            },
                                            sub: vec![],
                                        },
                                        Test {
                                            name: "RMP table initialized",
                                            gen_mask: SNP_MASK,
                                            run: Box::new(|| snp_ioctl(SnpStatusTest::Rmp)),
                                            meta: TestMetadata {
                                                category: TestCategory::PlatformInitialized,
                                                description: "Queries SNP platform status IS_RMP_INIT bit",
                                                fix_hint: "Run with sudo. Need CONFIG_KVM_AMD_SEV=y. Reboot if firmware updated",
                                            },
                                            sub: vec![],
                                        },
                                        Test {
                                            name: "Alias check",
                                            gen_mask: SNP_MASK,
                                            run: Box::new(|| snp_ioctl(SnpStatusTest::AliasCheck)),
                                            meta: TestMetadata {
                                                category: TestCategory::Compliance,
                                                description: "Queries SNP platform status ALIAS_CHECK_COMPLETE bit (CVE-2024-21944 mitigation)",
                                                fix_hint: "Update firmware/BIOS per AMD-SB-3015. Reboot required",
                                            },
                                            sub: vec![],
                                        },
                                    ],
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
                            meta: TestMetadata {
                                category: TestCategory::CpuInfo,
                                description: "Reads CPUID 0x8000001F EBX bits 11:6 for PA bit reduction value",
                                fix_hint: "Informational, no action needed",
                            },
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
                            meta: TestMetadata {
                                category: TestCategory::CpuInfo,
                                description: "Reads CPUID 0x8000001F EBX bits 5:0 for encryption bit position in page tables",
                                fix_hint: "Informational, no action needed",
                            },
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
                            meta: TestMetadata {
                                category: TestCategory::CpuInfo,
                                description: "Reads CPUID 0x8000001F ECX for maximum encrypted guest count",
                                fix_hint: "Informational, no action needed",
                            },
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
                            meta: TestMetadata {
                                category: TestCategory::CpuInfo,
                                description: "Reads CPUID 0x8000001F EDX for minimum SEV-only ASID value",
                                fix_hint: "Informational, no action needed",
                            },
                            sub: vec![],
                        },
                        Test {
                            name: "/dev/sev readable",
                            gen_mask: SEV_MASK,
                            run: Box::new(dev_sev_r),
                            meta: TestMetadata {
                                category: TestCategory::PlatformInitialized,
                                description: "Attempts to open /dev/sev device for reading",
                                fix_hint: "Run with sudo. Run: sudo modprobe ccp. Must be baremetal",
                            },
                            sub: vec![],
                        },
                        Test {
                            name: "/dev/sev writable",
                            gen_mask: SEV_MASK,
                            run: Box::new(dev_sev_w),
                            meta: TestMetadata {
                                category: TestCategory::PlatformInitialized,
                                description: "Attempts to open /dev/sev device for writing",
                                fix_hint: "Run with sudo. Must be baremetal",
                            },
                            sub: vec![],
                        },
                    ],
                },
                Test {
                    name: "Page flush MSR",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| {
                        let res = unsafe { x86_64::__cpuid(0x8000_001f) };

                        let msr_flag = if (res.eax & (0x1 << 2)) != 0 {
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
                    meta: TestMetadata {
                        category: TestCategory::CpuInfo,
                        description: "Checks CPUID 0x8000001F EAX bit 2 for page flush MSR optimization support",
                        fix_hint: "Informational, no action needed",
                    },
                    sub: vec![],
                },
            ],
        },
        Test {
            name: "KVM Support",
            gen_mask: SEV_MASK,
            run: Box::new(has_kvm_support),
            meta: TestMetadata {
                category: TestCategory::KvmConfig,
                description: "Opens /dev/kvm and queries KVM API version via ioctl",
                fix_hint: "Run with sudo. Run: sudo modprobe kvm kvm_amd. Enable SVM in BIOS",
            },
            sub: vec![
                Test {
                    name: "SEV enabled in KVM",
                    gen_mask: SEV_MASK,
                    run: Box::new(|| sev_enabled_in_kvm(SevGeneration::Sev)),
                    meta: TestMetadata {
                        category: TestCategory::KvmConfig,
                        description: "Reads /sys/module/kvm_amd/parameters/sev for \"1\" or \"Y\"",
                        fix_hint: "Temp: sudo modprobe kvm_amd sev=1. Persist: echo 'options kvm_amd sev=1' | sudo tee /etc/modprobe.d/kvm.conf",
                    },
                    sub: vec![],
                },
                Test {
                    name: "SEV-ES enabled in KVM",
                    gen_mask: ES_MASK,
                    run: Box::new(|| sev_enabled_in_kvm(SevGeneration::Es)),
                    meta: TestMetadata {
                        category: TestCategory::KvmConfig,
                        description: "Reads /sys/module/kvm_amd/parameters/sev_es for \"1\" or \"Y\"",
                        fix_hint: "Temp: sudo modprobe kvm_amd sev-es=1. Persist: echo 'options kvm_amd sev-es=1' | sudo tee /etc/modprobe.d/kvm.conf",
                    },
                    sub: vec![],
                },
                Test {
                    name: "SEV-SNP enabled in KVM",
                    gen_mask: SNP_MASK,
                    run: Box::new(|| sev_enabled_in_kvm(SevGeneration::Snp)),
                    meta: TestMetadata {
                        category: TestCategory::KvmConfig,
                        description: "Reads /sys/module/kvm_amd/parameters/sev_snp for \"1\" or \"Y\"",
                        fix_hint: "Temp: sudo modprobe kvm_amd sev_snp=1. Persist: echo 'options kvm_amd sev_snp=1' | sudo tee /etc/modprobe.d/kvm.conf. Need kernel 6.11+",
                    },
                    sub: vec![],
                },
            ],
        },
        Test {
            name: "memlock limit",
            gen_mask: SEV_MASK,
            run: Box::new(memlock_rlimit),
            meta: TestMetadata {
                category: TestCategory::Compliance,
                description: "Reads RLIMIT_MEMLOCK soft and hard limits via getrlimit syscall",
                fix_hint: "Set memlock unlimited in /etc/security/limits.conf",
            },
            sub: vec![],
        },
        Test {
            name: "Compare TCB values",
            gen_mask: SNP_MASK,
            run: Box::new(|| snp_ioctl(SnpStatusTest::Tcb)),
            meta: TestMetadata {
                category: TestCategory::Compliance,
                description: "Compares platform_tcb_version with reported_tcb_version from SNP_PLATFORM_STATUS",
                fix_hint: "Run: sudo snphost commit or sudo snphost config set (with args)",
            },
            sub: vec![],
        },
    ];

    tests
}

const INDENT: usize = 2;

pub fn cmd(quiet: bool, args: Ok) -> Result<()> {
    let tests = collect_tests();
    let results = run_test(&tests, SEV_MASK | ES_MASK | SNP_MASK);

    if !quiet {
        match (args.output_format(), args.verbosity()) {
            (OutputFormat::Json, _) => render_json(&results)?,
            (OutputFormat::Default, Verbosity::Default) => render_default(&results, 0),
            (OutputFormat::Default, Verbosity::Short) => render_short(&results),
            (OutputFormat::Default, Verbosity::Verbose) => render_verbose(&results),
        }
    }

    if !all_passed(&results) {
        std::process::exit(1);
    }
    Ok(())
}

fn run_test(tests: &[Test], mask: usize) -> Vec<TestResultNode> {
    let mut results = Vec::new();

    for t in tests {
        let node = if (t.gen_mask & mask) != t.gen_mask {
            // Test doesn't match generation mask - skip it and all children
            create_skip_node(t)
        } else {
            // Run the test
            let res = (t.run)();

            let sub = match res.stat {
                TestState::Pass => run_test(&t.sub, mask),
                TestState::Fail => create_skip_nodes(&t.sub),
                TestState::Skip => unreachable!(),
            };

            TestResultNode {
                result: res,
                meta: t.meta,
                sub,
            }
        };

        results.push(node);
    }

    results
}

fn create_skip_node(test: &Test) -> TestResultNode {
    TestResultNode {
        result: TestResult {
            name: test.name.to_string(),
            stat: TestState::Skip,
            mesg: None,
        },
        meta: test.meta,
        sub: create_skip_nodes(&test.sub),
    }
}

fn create_skip_nodes(tests: &[Test]) -> Vec<TestResultNode> {
    tests.iter().map(create_skip_node).collect()
}

fn all_passed(results: &[TestResultNode]) -> bool {
    results.iter().all(|n| {
        (n.result.stat == TestState::Pass || n.result.stat == TestState::Skip) && all_passed(&n.sub)
    })
}

fn render_default(results: &[TestResultNode], level: usize) {
    for node in results {
        let msg = match &node.result.mesg {
            Some(m) => format!(": {}", m),
            None => "".to_string(),
        };
        println!(
            "[ {:^4} ] {:width$}- {}{}",
            format!("{}", node.result.stat),
            "",
            node.result.name,
            msg,
            width = level
        );
        render_default(&node.sub, level + INDENT);
    }
}

fn render_short(results: &[TestResultNode]) {
    let mut passed = Vec::new();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();

    flatten_results(results, &mut passed, &mut failed, &mut skipped);

    if !failed.is_empty() {
        println!("{}", "Failures:".red());
        for e in &failed {
            let msg = match &e.mesg {
                Some(m) => format!(": {}", m),
                None => String::new(),
            };
            println!("[ {:^4} ] - {}{}", "FAIL".red(), e.name, msg);
        }
    }

    if !skipped.is_empty() {
        println!("\n{}:", "SKIPPED".yellow());
        for s in &skipped {
            println!("[ {:^4} ] - {}", "SKIP".yellow(), s.name);
        }
    }

    let counts = count_results(results);
    println!(
        "\n{} tests: {} passed, {} failed, {} skipped",
        counts.total, counts.passed, counts.failed, counts.skipped,
    );
    if failed.is_empty() {
        println!("{}", "All tests passed.".green());
    }
}

fn organize_by_category(results: &[TestResultNode]) -> Vec<(TestCategory, Vec<&TestResultNode>)> {
    let categories_order = [
        TestCategory::CpuSupport,
        TestCategory::CpuInfo,
        TestCategory::BiosConfigured,
        TestCategory::PlatformInitialized,
        TestCategory::KvmConfig,
        TestCategory::Compliance,
    ];

    // Flatten the tree structure into a list
    let mut all_nodes = Vec::new();
    flatten_nodes(results, &mut all_nodes);

    // Filter out skipped tests
    let all_nodes: Vec<_> = all_nodes
        .into_iter()
        .filter(|node| node.result.stat != TestState::Skip)
        .collect();

    // Group tests by category
    let mut categorized = Vec::new();
    for cat in &categories_order {
        let cat_entries: Vec<_> = all_nodes
            .iter()
            .filter(|node| node.meta.category == *cat)
            .copied()
            .collect();

        if !cat_entries.is_empty() {
            categorized.push((*cat, cat_entries));
        }
    }

    categorized
}

fn render_verbose(results: &[TestResultNode]) {
    let categorized = organize_by_category(results);

    for (cat, cat_entries) in &categorized {
        println!("\n=== {} ===", cat);
        for node in cat_entries {
            let status_colored = match node.result.stat {
                TestState::Pass => format!("{}", "PASS".green()),
                TestState::Fail => format!("{}", "FAIL".red()),
                TestState::Skip => format!("{}", "SKIP".yellow()),
            };
            let msg = match &node.result.mesg {
                Some(m) => {
                    let indented = m.replace('\n', "\n             ");
                    format!(": {}", indented.trim())
                }
                None => String::new(),
            };
            println!("  [ {:^4} ] {}{}", status_colored, node.result.name, msg);
            if !node.meta.description.is_empty() {
                println!("           {}", node.meta.description);
            }
            let hint_str = effective_hint(&node.meta, &node.result.mesg);
            if node.result.stat == TestState::Fail && !hint_str.is_empty() {
                println!("           {} {}", "Recommended:".yellow(), hint_str);
            }
        }
    }

    // Collect failed tests from all categories
    let failed_nodes: Vec<_> = categorized
        .iter()
        .flat_map(|(_, nodes)| nodes.iter())
        .filter(|node| node.result.stat == TestState::Fail)
        .collect();

    if !failed_nodes.is_empty() {
        println!("\n{}", "=== DETECTED ISSUES ===".red());
        for (i, node) in failed_nodes.iter().enumerate() {
            let hint_str = effective_hint(&node.meta, &node.result.mesg);
            println!("  {}. {} [FAIL]", i + 1, node.result.name);
            if !hint_str.is_empty() {
                println!("     {} {}", "Hint:".blue(), hint_str);
            }
        }
        println!();
    } else {
        println!("\n{}", "No issues detected.".green());
    }

    let counts = count_results(results);
    println!(
        "\n{} tests: {} passed, {} failed, {} skipped",
        counts.total, counts.passed, counts.failed, counts.skipped,
    );
}

fn strip_ansi(s: &str) -> String {
    String::from_utf8_lossy(&strip_ansi_escapes::strip(s)).to_string()
}

/// Parse TCB version comparison messages into structured JSON.
///
/// **IMPORTANT**: This parser depends on the exact format of TCB messages
/// generated in `snp_ioctl(SnpStatusTest::Tcb)`. If you modify the message
/// format in that test, update this parser accordingly.
///
/// Expected format:
/// ```text
/// TCB versions match \n\n Platform TCB version: <display> \n Reported TCB version: <display>
/// ```
/// or
/// ```text
/// The TCB versions did NOT match \n\n Platform TCB version: <display> \n Reported TCB version: <display>
/// ```
fn parse_tcb_message(msg: &str) -> Option<serde_json::Value> {
    // Parse TCB version messages into structured JSON
    if !msg.contains("TCB version") {
        return None;
    }

    let parse_tcb_fields = |section: &str| -> serde_json::Value {
        let mut fields = serde_json::Map::new();
        for line in section.lines() {
            let line = line.trim();
            // Skip the "TCB Version:" header
            if line == "TCB Version:" || line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase().replace(' ', "_");
                let value = value.trim();
                fields.insert(key, serde_json::json!(value));
            }
        }
        serde_json::Value::Object(fields)
    };

    let parts: Vec<&str> = msg.split("Platform TCB version:").collect();
    if parts.len() != 2 {
        return None;
    }

    let status = parts[0].trim();
    let remainder = parts[1];

    let tcb_parts: Vec<&str> = remainder.split("Reported TCB version:").collect();
    if tcb_parts.len() != 2 {
        return None;
    }

    let platform = parse_tcb_fields(tcb_parts[0]);
    let reported = parse_tcb_fields(tcb_parts[1]);

    Some(serde_json::json!({
        "match": status == "TCB versions match",
        "platform_tcb_version": platform,
        "reported_tcb_version": reported,
    }))
}

fn render_json(results: &[TestResultNode]) -> Result<()> {
    let mut all_nodes = Vec::new();
    flatten_nodes(results, &mut all_nodes);

    let all_nodes: Vec<_> = all_nodes
        .into_iter()
        .filter(|node| node.result.stat != TestState::Skip)
        .collect();

    let tests: Vec<_> = all_nodes
        .iter()
        .map(|node| {
            let mut test = serde_json::json!({
                "name": strip_ansi(&node.result.name),
                "status": node.result.stat,
                "category": node.meta.category,
                "description": node.meta.description,
            });

            if let Some(ref msg) = node.result.mesg {
                if let Some(structured) = parse_tcb_message(msg) {
                    test["message"] = structured;
                } else {
                    test["message"] = serde_json::json!(strip_ansi(msg));
                }
            }

            if node.result.stat == TestState::Fail {
                let hint = effective_hint(&node.meta, &node.result.mesg);
                if !hint.is_empty() {
                    test["fix_hint"] = serde_json::json!(hint);
                }
            }

            test
        })
        .collect();

    let failures: Vec<_> = all_nodes
        .iter()
        .filter(|node| node.result.stat == TestState::Fail)
        .map(|node| {
            serde_json::json!({
                "name": strip_ansi(&node.result.name),
                "hint": effective_hint(&node.meta, &node.result.mesg),
            })
        })
        .collect();

    let counts = count_results(results);

    let output = serde_json::json!({
        "tests": tests,
        "failures": failures,
        "summary": {
            "total": counts.total,
            "passed": counts.passed,
            "failed": counts.failed,
            "skipped": counts.skipped
        }
    });

    serde_json::to_writer_pretty(std::io::stdout(), &output)?;
    println!();
    Ok(())
}

fn flatten_nodes<'a>(results: &'a [TestResultNode], output: &mut Vec<&'a TestResultNode>) {
    for node in results {
        output.push(node);
        flatten_nodes(&node.sub, output);
    }
}

fn flatten_results<'a>(
    results: &'a [TestResultNode],
    passed: &mut Vec<&'a TestResult>,
    failed: &mut Vec<&'a TestResult>,
    skipped: &mut Vec<&'a TestResult>,
) {
    for node in results {
        match node.result.stat {
            TestState::Pass => passed.push(&node.result),
            TestState::Fail => failed.push(&node.result),
            TestState::Skip => skipped.push(&node.result),
        }
        flatten_results(&node.sub, passed, failed, skipped);
    }
}

struct TestCounts {
    passed: usize,
    failed: usize,
    skipped: usize,
    total: usize,
}

fn count_results(results: &[TestResultNode]) -> TestCounts {
    let mut passed = Vec::new();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();

    flatten_results(results, &mut passed, &mut failed, &mut skipped);

    let passed_count = passed.len();
    let failed_count = failed.len();
    let skipped_count = skipped.len();
    let total = passed_count + failed_count + skipped_count;

    TestCounts {
        passed: passed_count,
        failed: failed_count,
        skipped: skipped_count,
        total,
    }
}

fn dev_sev_r() -> TestResult {
    let (stat, mesg) = match dev_sev_rw(fs::OpenOptions::new().read(true)) {
        Ok(_) => (TestState::Pass, None),
        Err(e) => (TestState::Fail, Some(format!("Not readable: {}", e))),
    };

    TestResult {
        name: "/dev/sev readable".to_string(),
        stat,
        mesg,
    }
}

fn dev_sev_w() -> TestResult {
    let (stat, mesg) = match dev_sev_rw(fs::OpenOptions::new().write(true)) {
        Ok(_) => (TestState::Pass, None),
        Err(e) => (TestState::Fail, Some(format!("Not writable: {}", e))),
    };

    TestResult {
        name: "/dev/sev writable".to_string(),
        stat,
        mesg,
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
                    (TestState::Pass, None)
                } else {
                    (
                        TestState::Fail,
                        Some(format!(
                            "Error - contents read from {}: {}",
                            path_loc,
                            result.trim()
                        )),
                    )
                }
            }
            Err(e) => (
                TestState::Fail,
                Some(format!("Error - (unable to read {}): {}", path_loc, e,)),
            ),
        }
    } else {
        (
            TestState::Fail,
            Some(format!("Error - {} does not exist", path_loc)),
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
        mesg,
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
    let (testres, mesg) = match (raw_value >> 23) & 1 {
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
    let (testres, mesg) = match (raw_value >> 24) & 1 {
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
            mesg: format!("0x{:x} - 0x{:x}", rmp_base, rmp_end).into(),
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
            // NOTE: This message format is parsed by `parse_tcb_message()` for JSON output.
            // If you change this format, update that parser as well.
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
            if status.is_rmp_init.is_rmp_init() {
                TestResult {
                    name: format!("{}", SnpStatusTest::Rmp),
                    stat: TestState::Pass,
                    mesg: None,
                }
            } else {
                TestResult {
                    name: format!("{}", SnpStatusTest::Rmp),
                    stat: TestState::Fail,
                    mesg: None,
                }
            }
        }
        SnpStatusTest::AliasCheck => {
            if status.is_rmp_init.alias_check_complete() {
                TestResult {
                    name: format!("{}", SnpStatusTest::AliasCheck),
                    stat: TestState::Pass,
                    mesg: Some(
                        "Completed since last system update, no aliasing addresses".to_string(),
                    ),
                }
            } else {
                TestResult {
                    name: format!("{}", SnpStatusTest::AliasCheck),
                    stat: TestState::Fail,
                    mesg: None,
                }
            }
        }
        SnpStatusTest::Snp => {
            if status.state == 1 {
                TestResult {
                    name: format!("{}", SnpStatusTest::Snp),
                    stat: TestState::Pass,
                    mesg: None,
                }
            } else {
                TestResult {
                    name: format!("{}", SnpStatusTest::Snp),
                    stat: TestState::Fail,
                    mesg: None,
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
                    mesg: Some("Initialized, currently running a guest".to_string()),
                }
            } else if status.state == State::Initialized {
                TestResult {
                    name: format!("{}", SevStatusTests::Sev),
                    stat: TestState::Pass,
                    mesg: Some("Initialized, no guests running".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", SevStatusTests::Sev),
                    stat: TestState::Fail,
                    mesg: Some("Uninitialized".to_string()),
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
                    mesg: format!("{}", status.build.version).into(),
                }
            }
        }

        SevStatusTests::SevEs => {
            let res = match (status.flags.bits() >> 8) & 1 {
                1 => TestState::Pass,
                0 => TestState::Fail,
                _ => unreachable!(),
            };
            TestResult {
                name: format!("{}", SevStatusTests::SevEs),
                stat: res,
                mesg: None,
            }
        }
    }
}
