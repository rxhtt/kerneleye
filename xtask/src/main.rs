use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Opt {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Build userspace and eBPF kernel probe
    Build {
        #[arg(short = 'j', long)]
        jobs: Option<usize>,
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    match opt.command {
        Commands::Build { jobs, release } => {
            let mut cmd = Command::new("cargo");
            cmd.arg("build").arg("--package").arg("exec-snoop");
            if let Some(j) = jobs {
                cmd.arg("-j").arg(j.to_string());
            }
            if release {
                cmd.arg("--release");
            }
            let status = cmd.status().context("failed to execute cargo build")?;
            if !status.success() {
                bail!("cargo build failed with status: {status}");
            }

            // Ensure target/bpfel-unknown-none/debug/exec-snoop exists
            let profile = if release { "release" } else { "debug" };
            let ebpf_target_dir = std::path::Path::new("target/bpfel-unknown-none").join(profile);
            std::fs::create_dir_all(&ebpf_target_dir)?;
            let ebpf_dest = ebpf_target_dir.join("exec-snoop");

            // Look for compiled ebpf in target/<profile>/build/exec-snoop-*/out/exec-snoop
            let build_dir = std::path::Path::new("target").join(profile).join("build");
            if let Ok(entries) = std::fs::read_dir(&build_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map_or(false, |s| s.starts_with("exec-snoop-"))
                    {
                        let candidate = path.join("out/exec-snoop");
                        if candidate.exists() {
                            let _ = std::fs::copy(&candidate, &ebpf_dest);
                            break;
                        }
                    }
                }
            }

            // Also check the debug target if release was not specified or vice versa
            let debug_ebpf = std::path::Path::new("target/bpfel-unknown-none/debug/exec-snoop");
            if !debug_ebpf.exists() && ebpf_dest.exists() {
                std::fs::create_dir_all("target/bpfel-unknown-none/debug")?;
                let _ = std::fs::copy(&ebpf_dest, debug_ebpf)?;
            }

            println!("Build complete!");
            println!("Kernel probe target: {}", debug_ebpf.display());
            println!("Userspace binary target: target/debug/exec-snoop");
        }
    }
    Ok(())
}
