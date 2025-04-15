use ssh_zellij::{Args, zellij_attach};

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse().validate()?;
    zellij_attach(&args.ssh_addr).await
}
