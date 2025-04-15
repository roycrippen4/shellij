use shellij::{Args, shellij};

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse().validate()?;
    shellij(&args.ssh_addr).await
}
