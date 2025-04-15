#![allow(unused)]
use anyhow::{Result, anyhow};
use clap::Parser;
use core::fmt;
use crossterm::event::{Event, KeyCode, poll, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use indoc::formatdoc;
use openssh::{KnownHosts, Session};

use std::collections::HashMap;
use std::io::Write;
use std::process::{self};
use std::process::{Command, Stdio};
use std::time::Duration;

use ssh_zellij::{Args, Zesh, validate};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !validate::args_are_valid(&args) || !validate::env_is_valid() {
        process::exit(1);
    }

    // ssh connected and zellij is on remote's PATH
    let ssh = ssh_connect(&args.ssh_addr).await?;

    // if we continue past this we have zellij on remote
    let ssh = has_zellij(ssh).await?;
    let (ssh, zs) = get_zellij_sessions(ssh).await?;

    if zs.is_empty() {
        println!("No active sessions found. Create one? (Enter for yes, any other key for no)");

        if poll_for_cr()? {
            todo!("Create a new session");
        } else {
            todo!("Do not create a new session");
        }
    }

    if zs.len() == 1 {
        println!("Only one session found. Connecting...");
        ssh.command("zellij").arg("attach").output().await?;
        ssh_close(ssh).await?;
        return Ok(());
    }

    let mut fzf = Command::new("fzf")
        .arg("--ansi")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    {
        let stdin = fzf.stdin.as_mut().expect("failed to capture stdin");
        let items: Vec<_> = zs.iter().map(|s| s.raw.clone()).collect();
        stdin.write_all(items.join("\n").as_bytes())?;
    }

    let output = fzf.wait_with_output()?;

    if !output.status.success() {
        ssh_close(ssh);
        return Err(anyhow!("Fzf exited with failure code"));
    }

    let raw_choice = String::from_utf8(output.stdout)
        .expect("fzf produced invalid utf-8")
        .trim()
        .to_string();

    let map: HashMap<String, Zesh> = HashMap::from_iter(zs.into_iter().map(|z| (z.raw.clone(), z)));

    ssh_close(ssh).await
}

/// Polls the keyboard. Return true if the next key pressed is <CR>.
pub fn poll_for_cr() -> Result<bool> {
    enable_raw_mode()?;
    loop {
        if poll(Duration::from_millis(100))? {
            let event = read()?;
            if event == Event::Key(KeyCode::Enter.into()) {
                disable_raw_mode()?;
                return Ok(true);
            } else {
                disable_raw_mode()?;
                return Ok(false);
            }
        }
    }
}

pub async fn ssh_connect(ssh_addr: &str) -> Result<Session> {
    println!("Attempting to contact remote...");
    let ssh = Session::connect(ssh_addr, KnownHosts::Strict).await?;
    println!("Connection established");
    Ok(ssh)
}

pub async fn ssh_close(ssh: Session) -> Result<()> {
    println!("Closing connection...");
    ssh.close().await?;
    println!("Connection closed");
    Ok(())
}

pub async fn has_zellij(ssh: Session) -> Result<Session> {
    println!("Checking for zellij executable on remote PATH...");

    let stdout_is_empty = ssh
        .command("which")
        .arg("zellij")
        .output()
        .await?
        .stdout
        .is_empty();

    if stdout_is_empty {
        let err = "Remote does not have Zellij in PATH. Aborting.";
        eprintln!("{err}");
        ssh_close(ssh).await?;
        return Err(anyhow!(err));
    }

    Ok(ssh)
}

pub async fn get_zellij_sessions(ssh: Session) -> Result<(Session, Vec<Zesh>)> {
    let zessions = ssh.command("zellij").arg("ls").output().await?.stdout;

    if zessions.is_empty() {
        let err = "Command `zellij ls` failed on remote. Aborting.";
        eprintln!("{err}");
        ssh_close(ssh).await?;
        return Err(anyhow!(err));
    }

    let zessions = String::from_utf8(zessions)?;
    if zessions.contains("No active zellij sessions found.") {
        return Ok((ssh, vec![]));
    }

    let zessions = zessions
        .trim()
        .split('\n')
        .flat_map(Zesh::try_from)
        .collect();

    Ok((ssh, zessions))
}
