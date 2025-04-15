use ansi_term::Color;
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use indoc::{eprintdoc, formatdoc};

use crossterm::event::{Event, KeyCode, poll, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use std::fmt;
use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "shellij")]
#[command(about = "Helps you SSH directly into Zellij", long_about = None, version)]
pub struct Cli {
    #[arg(index = 1, required = true)]
    pub ssh_addr: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Lists Zellij sessions over SSH
    List,

    /// Create and attach to a new Zellij session over SSH
    #[command(arg_required_else_help = true)]
    Create {
        /// Name of the new session
        session_name: String,
    },

    /// Delete a Zellij session over SSH
    #[command(arg_required_else_help = true)]
    Delete {
        /// Name of the session to delete
        #[arg(value_name = "SESSION NAME")]
        session_name: String,

        /// Force delete a session
        #[arg(
            long,
            short,
            action = clap::ArgAction::SetTrue,
            required = false,
            help ="Forces Zellij to delete a session. Required if the session is active."
        )]
        force: bool,
    },
}

impl Cli {
    pub fn validate(self) -> Result<Self> {
        if !self.args_are_valid() || !Self::env_is_valid() {
            return Err(anyhow!("Goodbye!"));
        }

        Ok(self)
    }

    fn args_are_valid(&self) -> bool {
        let error = Color::Red.paint("error: ");
        let usage_lbl = Color::White.bold().underline().paint("Usage");
        let exe = Color::White.bold().paint("ssh_zellij");
        let help = Color::White.bold().paint("--help");
        let usr = Color::Red.paint("<user>");
        let at = Color::Red.paint("@");
        let i = Color::Red.paint("<ip>");
        let addr = Color::White.bold().paint(self.ssh_addr.clone());

        let usage = formatdoc! {"
        {usage_lbl}: {exe} <SSH_ADDR>

        For more information, try '{help}'
        "};

        let Some((user, ip)) = self.ssh_addr.split_once("@") else {
            eprintdoc! {"
            {error} Malformed ssh address '{addr}':
              <user>{at}<ip>
                    ^ separator not found

            {usage}"};
            return false;
        };

        if user.is_empty() {
            eprintdoc! {"
            {error} Malformed ssh address '{addr}':
              {usr}@<ip>
               ^^^^ user not found

            {usage}"};

            return false;
        }

        if ip.is_empty() {
            eprintdoc! {"
            {error} Malformed ssh address '{addr}':
              <user>@{i}
                      ^^ ip not found

            {usage}"};

            return false;
        }

        if ip.parse::<IpAddr>().is_err() {
            eprintdoc! {"
            {error} Malformed ssh address '{addr}':
              <user>@{i}
                      ^^ invalid ip address

            {usage}"};
            return false;
        }

        true
    }

    fn env_is_valid() -> bool {
        let has_fzf = !Command::new("which")
            .arg("fzf")
            .output()
            .expect("Failed to check for fzf")
            .stdout
            .is_empty();

        if !has_fzf {
            let msg = "Failed to find fzf executable on PATH. Ensure fzf is executable to use this program";
            eprintln!("{msg}");
            return false;
        }

        let has_zellij = !Command::new("which")
            .arg("zellij")
            .output()
            .expect("Failed to check for zellij")
            .stdout
            .is_empty();

        if !has_zellij {
            eprintln!(
                "Failed to find zellij executable on PATH. Ensure zellij is executable to use this program"
            );
        }

        true
    }
}

/// Polls the keyboard. Return true if the next key pressed is <CR>.
fn poll_for_cr() -> Result<bool> {
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

/// Puts remote zellij sessions into local fzf picker
fn fzf(zs: Vec<Zesh>, zs_raw: String) -> Result<Zesh> {
    let mut fzf = Command::new("fzf")
        .args([
            "--ansi",
            "--with-nth",
            "2..",
            "--header",
            "Which session do you want to attach to?",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let stdin = fzf.stdin.as_mut().expect("failed to capture stdin");
    stdin.write_all(zs_raw.as_bytes())?;

    let output = fzf.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("Fzf exited with failure code"));
    }

    let raw_choice = String::from_utf8(output.stdout).expect("fzf produced invalid utf-8");
    let raw_choice = raw_choice.trim();

    let Some((idx, _rest)) = raw_choice.split_once(' ') else {
        let errmsg = "Failed to parse choice output from fzf.";
        eprintln!("{errmsg}");
        return Err(anyhow!(errmsg));
    };

    let choice_idx = idx.parse::<usize>()?;
    Ok(zs[choice_idx].clone())
}

pub fn shellij_create(ssh_addr: &str, session_name: &str) -> Result<()> {
    Command::new("ssh")
        .arg("-t")
        .arg(ssh_addr)
        .arg(format!("zellij -s {session_name}"))
        .status()?;

    Ok(())
}

pub fn shellij_delete(ssh_addr: &str, session_name: &str, force: bool) -> Result<()> {
    let zellij_cmd = if force {
        format!("zellij delete-session {session_name}")
    } else {
        format!("zellij delete-session {session_name} --force")
    };

    Command::new("ssh")
        .arg(ssh_addr)
        .arg(&zellij_cmd)
        .status()?;

    Ok(())
}

pub fn shellij_list(ssh_addr: &str) -> Result<()> {
    let (_, stdout) = zellij_list_sessions(ssh_addr)?;

    if stdout.is_empty() {
        println!("No Zellij sessions found.");
        return Ok(());
    }

    println!("\nSessions Found:");
    println!("{stdout}");

    Ok(())
}

/// Attaches to a remote zellij session over ssh
pub fn shellij(ssh_addr: &str) -> Result<()> {
    let (zs, stdout) = zellij_list_sessions(ssh_addr)?;

    let zs_raw = stdout
        .lines()
        .enumerate()
        .fold(String::new(), |mut output, (i, l)| {
            let _ = writeln!(output, "{i} {}", l);
            output
        });

    if zs.is_empty() {
        println!("No active sessions found");
        println!("Create one? (Enter for yes, any other key for no)");

        if poll_for_cr()? {
            Command::new("ssh")
                .arg("-t")
                .arg(ssh_addr)
                .arg("zellij attach --create")
                .status()?;
            return Ok(());
        } else {
            println!("No sessions created. Goodbye!");
            return Ok(());
        }
    }

    if zs.len() == 1 {
        println!("Only one session found. Connecting...");
        Command::new("ssh")
            .arg("-t")
            .arg(ssh_addr)
            .arg("zellij")
            .arg("attach")
            .status()?;
        return Ok(());
    }

    let session_name = fzf(zs, zs_raw)?.name;
    println!("Attaching to {session_name}...");
    Command::new("ssh")
        .arg("-t")
        .arg(ssh_addr)
        .arg(format!("zellij attach {session_name}"))
        .status()?;

    Ok(())
}

/// Gets the list of zellij sessions from remote over ssh
fn zellij_list_sessions(ssh_addr: &str) -> Result<(Vec<Zesh>, String)> {
    let zellij_out = Command::new("ssh")
        .arg(ssh_addr)
        .arg("zellij ls -n")
        .output()?;

    let stdout = String::from_utf8(zellij_out.stdout)?;
    let stderr = String::from_utf8(zellij_out.stderr)?;

    if stderr.contains("No active zellij sessions found.") {
        return Ok((vec![], stdout));
    }

    if stdout.is_empty() {
        let err = "Command `zellij ls` failed on remote. Aborting.";
        eprintln!("{err}");
        return Err(anyhow!(err));
    }

    let zs = stdout.trim().split('\n').flat_map(Zesh::try_from).collect();

    // ssh.close().await?;
    Ok((zs, stdout.trim().to_string()))
}

#[derive(Debug, Clone)]
struct Zesh {
    pub name: String,
    pub created_at: String,
    pub exited: bool,
}

impl fmt::Display for Zesh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Zesh {
            name,
            created_at,
            exited,
        } = self;

        let s = formatdoc! {"
        {{
            name: {name}
            created_at: {created_at}
            exited: {exited}
        }}
        "};

        write!(f, "{s}")
    }
}

impl TryFrom<&str> for Zesh {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let Some((name, rest)) = s.split_once(" ") else {
            println!("Failed to parse session list from remote zellij!");
            return Err(anyhow!("Failed to parse session list from remote zellij!"));
        };

        if name.is_empty() {
            let errmsg = "Failed to parse session name from remote zellij session list!";
            eprintln!("{errmsg}");
            return Err(anyhow!(errmsg));
        }

        if rest.is_empty() {
            let errmsg = "Unexpected end of input while parsing zellij session list!";
            eprintln!("{errmsg}");
            return Err(anyhow!(errmsg));
        }

        let Some((created_at, rest)) = rest[1..].split_once("]") else {
            eprintln!("Failed to parse session creation timestamp!");
            return Err(anyhow!("Failed to parse session creation timestamp!"));
        };

        let created_at = created_at.trim().to_string();
        let name = name.to_string();
        let rest = rest.trim();

        if rest.is_empty() {
            return Ok(Zesh {
                name,
                created_at,
                exited: false,
            });
        }

        if rest.contains("EXITED") {
            return Ok(Zesh {
                name,
                created_at,
                exited: true,
            });
        }

        println!("FAILED TO RETURN ZESH");

        Err(anyhow!("Failed to parse session exit status!"))
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn parse_zesh() {
        let s =
            "friendly-tiger [Created 1month 9days 13h 33m 5s ago] (EXITED - attach to resurrect)";

        let zesh = Zesh::try_from(s);
        assert!(zesh.is_ok());

        let s = "considerate-hill [Created 4s ago] ";
        let zesh = Zesh::try_from(s);
        assert!(zesh.is_ok());
    }
}
