use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "exec-snoop-ebpf")
        .ok_or_else(|| anyhow!("exec-snoop-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    let out_dir = std::env::var("OUT_DIR")?;
    let src = std::path::Path::new(&out_dir).join("exec-snoop");
    for prefix in &["..", "../.."] {
        for profile in &["debug", "release"] {
            let dest_dir = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR")?)
                .join(prefix)
                .join("target/bpfel-unknown-none")
                .join(profile);
            let _ = std::fs::create_dir_all(&dest_dir);
            let _ = std::fs::copy(&src, dest_dir.join("exec-snoop"));
        }
    }
    Ok(())
}
