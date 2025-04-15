use clap::Parser;

pub mod ip;
pub mod validate;
mod zesh;

pub use zesh::Zesh;

#[derive(Parser, Debug)]
#[command(version)]
#[command(about = "Helps you SSH directly into Zellij")]
pub struct Args {
    #[arg(index = 1, required = true)]
    pub ssh_addr: String,
}
