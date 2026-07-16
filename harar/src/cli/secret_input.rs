use anyhow::{Result, anyhow};
use clap::Args;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

/// A secret input is deliberately never represented as a command-line value.
/// Humans get a no-echo prompt; automation must use stdin, an environment
/// variable named by `--secret-env`, or a protected file.
#[derive(Debug, Args)]
pub struct SecretInput {
    #[arg(long, conflicts_with_all = ["secret_file", "secret_env"])]
    secret_stdin: bool,
    #[arg(long, value_name = "PATH", conflicts_with_all = ["secret_stdin", "secret_env"])]
    secret_file: Option<PathBuf>,
    #[arg(long, value_name = "NAME", conflicts_with_all = ["secret_stdin", "secret_file"])]
    secret_env: Option<String>,
}

impl SecretInput {
    pub fn read(self, prompt: &str) -> Result<String> {
        let value = if self.secret_stdin {
            read_stdin()?
        } else if let Some(path) = self.secret_file {
            fs::read_to_string(&path)
                .map_err(|err| anyhow!("read secret file {}: {err}", path.display()))?
        } else if let Some(name) = self.secret_env {
            std::env::var(&name)
                .map_err(|_| anyhow!("secret environment variable {name} is not set"))?
        } else if std::io::stdin().is_terminal() {
            prompt_no_echo(prompt)?
        } else {
            read_stdin()?
        };
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(anyhow!("secret input is empty"));
        }
        Ok(value)
    }
}

fn read_stdin() -> Result<String> {
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    Ok(value)
}

fn prompt_no_echo(prompt: &str) -> Result<String> {
    eprint!("{prompt}: ");
    std::io::stderr().flush()?;
    let fd = libc::STDIN_FILENO;
    // SAFETY: tcgetattr/tcsetattr operate only on the calling process's stdin.
    unsafe {
        let mut original = std::mem::zeroed::<libc::termios>();
        if libc::tcgetattr(fd, &mut original) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(fd, libc::TCSANOW, &hidden) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = (|| -> Result<String> {
            let mut value = String::new();
            std::io::stdin().read_line(&mut value)?;
            Ok(value)
        })();
        let restore = libc::tcsetattr(fd, libc::TCSANOW, &original);
        eprintln!();
        if restore != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        secret: SecretInput,
    }

    #[test]
    fn parser_has_no_secret_value_argument() {
        assert!(Command::try_parse_from(["harar", "--token", "leak"]).is_err());
        assert!(Command::try_parse_from(["harar", "--secret-env", "HARAR_TOKEN"]).is_ok());
        assert!(Command::try_parse_from(["harar", "--secret-file", "/run/secret"]).is_ok());
    }
}
