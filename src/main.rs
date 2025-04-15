use shellij::Commands;
use shellij::{Cli, shellij, shellij_create, shellij_delete, shellij_list};

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse().validate()?;

    // No subcommands
    let Some(command) = cli.command else {
        return shellij(&cli.ssh_addr);
    };

    match command {
        // Commands::KillSessions => shellij_kill_session()?,
        Commands::List => shellij_list(&cli.ssh_addr)?,
        Commands::Create { session_name } => shellij_create(&cli.ssh_addr, &session_name)?,
        Commands::Delete {
            session_name,
            force,
        } => shellij_delete(&cli.ssh_addr, &session_name, force)?,
    }

    Ok(())
}
