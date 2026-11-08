//! Embeds harar edge (../edge) in the binary, so `harar edge init` writes the
//! same files the edge's own tests and CI check: the core file, each
//! platform's files under edge/platforms/<platform>/, and layout.json, which
//! says where the core goes for each platform. Nothing is listed by hand.
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let edge = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../edge");
    let edge = edge.canonicalize().expect("../edge exists next to server/");
    println!("cargo:rerun-if-changed={}", edge.join("harar-edge.ts").display());
    println!("cargo:rerun-if-changed={}", edge.join("platforms").display());

    let mut files = Vec::new();
    let platforms = edge.join("platforms");
    let mut names: Vec<_> = fs::read_dir(&platforms).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect();
    names.sort();
    for dir in names {
        let platform = dir.file_name().unwrap().to_str().unwrap().to_owned();
        for path in walk(&dir) {
            println!("cargo:rerun-if-changed={}", path.display());
            let rel = path.strip_prefix(&dir).unwrap().to_str().unwrap().replace('\\', "/");
            files.push(format!("    ({platform:?}, {rel:?}, include_str!({:?})),", path.display().to_string()));
        }
    }
    let out = format!(
        "/// edge/harar-edge.ts\npub static CORE: &str = include_str!({core:?});\n\
         /// edge/platforms/layout.json\npub static LAYOUT: &str = include_str!({layout:?});\n\
         /// (platform, path in the written folder, contents)\npub static PLATFORM_FILES: &[(&str, &str, &str)] = &[\n{files}\n];\n",
        core = edge.join("harar-edge.ts").display().to_string(),
        layout = platforms.join("layout.json").display().to_string(),
        files = files.join("\n"),
    );
    fs::write(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("edge_files.rs"), out).unwrap();
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.file_name().is_some_and(|n| n != "layout.json") {
            out.push(path);
        }
    }
    out
}
