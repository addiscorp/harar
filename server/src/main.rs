mod agent;
mod cli;
mod common;
mod dotenv;
#[cfg(target_os = "macos")]
mod enclave;
mod mask;
mod master_key;
mod primary;
mod screen;
mod ssh;
mod store;
mod template;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
