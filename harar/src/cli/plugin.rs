use crate::cli::secret_input::SecretInput;
use crate::cli::{SocketArgs, print_json};
use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

/// A CLI harar can hand a token to, and where that CLI would otherwise keep it.
struct Tool {
    name: &'static str,
    /// The variable the tool reads its token from.
    env: &'static str,
    /// Where the tool stores a token of its own, relative to $HOME.
    own_token_files: &'static [&'static str],
    logout: &'static str,
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "gh",
        env: "GH_TOKEN",
        own_token_files: &[".config/gh/hosts.yml"],
        logout: "gh auth logout",
    },
    Tool {
        name: "npm",
        env: "NPM_TOKEN",
        own_token_files: &[".npmrc"],
        logout: "remove the _authToken line from ~/.npmrc and add `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`",
    },
    Tool {
        name: "wrangler",
        env: "CLOUDFLARE_API_TOKEN",
        own_token_files: &["Library/Preferences/.wrangler/config/default.toml", ".config/.wrangler/config/default.toml", ".wrangler/config/default.toml"],
        logout: "wrangler logout",
    },
];

fn tool(name: &str) -> Result<&'static Tool> {
    TOOLS.iter().find(|tool| tool.name == name).ok_or_else(|| {
        let known: Vec<_> = TOOLS.iter().map(|tool| tool.name).collect();
        anyhow!("harar has no plugin for {name}; it knows {}", known.join(", "))
    })
}

fn vault_key(tool: &Tool) -> String {
    format!("plugins/{}/token", tool.name)
}

/// Give CLIs their tokens from the vault instead of their own config files.
#[derive(Debug, Args)]
pub struct Plugin {
    #[command(subcommand)]
    command: PluginCommand,
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    /// Store a tool's token and print the shell alias that uses it.
    Init(Init),
    /// Run a tool with its token from the vault, for that process only.
    Run(Run),
    /// List the tools harar has plugins for.
    List,
}

#[derive(Debug, Args)]
struct Init {
    #[command(flatten)]
    socket: SocketArgs,
    tool: String,
    #[command(flatten)]
    token: SecretInput,
}

#[derive(Debug, Args)]
struct Run {
    #[command(flatten)]
    socket: SocketArgs,
    tool: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

pub async fn run(cmd: Plugin) -> Result<()> {
    match cmd.command {
        PluginCommand::Init(cmd) => init(cmd).await,
        PluginCommand::Run(cmd) => exec(cmd).await,
        PluginCommand::List => print_json(&TOOLS.iter().map(|t| serde_json::json!({ "tool": t.name, "env": t.env })).collect::<Vec<_>>()),
    }
}

async fn init(cmd: Init) -> Result<()> {
    let tool = tool(&cmd.tool)?;
    let token = cmd.token.read(&format!("{} token", tool.name))?;
    let key = vault_key(tool);
    VaultClient::from_socket_path(cmd.socket.socket)
        .put(&key, &token)
        .await
        .with_context(|| format!("store the {} token", tool.name))?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let leftovers: Vec<PathBuf> = home
        .iter()
        .flat_map(|home| tool.own_token_files.iter().map(move |file| home.join(file)))
        .filter(|path| path.exists())
        .collect();
    print_json(&serde_json::json!({
        "ok": true,
        "stored": key,
        "alias": format!("alias {}='harar plugin run {} --'", tool.name, tool.name),
        "next": "Add the alias to your shell's rc file.",
        "own_token_files": leftovers,
        "remove_own_token": (!leftovers.is_empty()).then_some(tool.logout),
    }))
}

async fn exec(cmd: Run) -> Result<()> {
    let tool = tool(&cmd.tool)?;
    let key = vault_key(tool);
    let token = VaultClient::from_socket_path(cmd.socket.socket)
        .get(&key)
        .await
        .with_context(|| format!("read {key}; run `harar plugin init {}` first", tool.name))?;
    // The tool keeps its terminal: it runs in harar's place, not behind a pipe.
    let err = std::process::Command::new(tool.name)
        .args(&cmd.args)
        .env(tool.env, token)
        .exec();
    Err(anyhow!("start {}: {err}", tool.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_a_distinct_name_and_variable() {
        let mut names: Vec<_> = TOOLS.iter().map(|t| t.name).collect();
        let mut envs: Vec<_> = TOOLS.iter().map(|t| t.env).collect();
        names.dedup();
        envs.dedup();
        assert_eq!(names.len(), TOOLS.len());
        assert_eq!(envs.len(), TOOLS.len());
    }

    #[test]
    fn unknown_tools_are_named_in_the_error() {
        let err = tool("kubectl").err().unwrap().to_string();
        assert!(err.contains("kubectl") && err.contains("gh"));
    }
}
