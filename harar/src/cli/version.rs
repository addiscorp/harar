use anyhow::Result;
use clap::Args;

#[derive(Debug, Args)]
pub struct Version {}

pub fn run(_: Version) -> Result<()> {
    println!("harar {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_command_is_available() {
        assert!(Version::augment_args(clap::Command::new("version")).get_name() == "version");
    }
}
