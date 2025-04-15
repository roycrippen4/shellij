use ansi_term::Color;
use anyhow::{Result, anyhow};
use clap::Parser;
use indoc::{eprintdoc, formatdoc};
use openssh::{KnownHosts, Session};
use regex::Regex;

use crossterm::event::{Event, KeyCode, poll, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use std::fmt;
use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(version)]
#[command(about = "Helps you SSH directly into Zellij")]
pub struct Args {
    #[arg(index = 1, required = true)]
    pub ssh_addr: String,
}

impl Args {
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

    For more information, try '{help}'"
        };

        let Some((user, ip)) = self.ssh_addr.split_once("@") else {
            eprintdoc! {"
        {error} Malformed ssh address '{addr}':
          <user>{at}<ip>
                ^ separator not found

        {usage}
        "};
            return false;
        };

        if user.is_empty() {
            eprintdoc! {"
        {error} Malformed ssh address '{addr}':
          {usr}@<ip>
           ^^^^ user not found

        {usage}
        "};

            return false;
        }

        if ip.is_empty() {
            eprintdoc! {"
        {error} Malformed ssh address '{addr}':
          <user>@{i}
                  ^^ ip not found

        {usage}
        "};

            return false;
        }

        if !is_ip(ip) {
            eprintdoc! {"
        {error} Malformed ssh address '{addr}':
          <user>@{i}
                  ^^ invalid ip address

        {usage}
        "};

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

/// Attaches to a remote zellij session over ssh
pub async fn shellij(ssh_addr: &str) -> Result<()> {
    let (zs, zs_raw) = zellij_list_sessions(ssh_addr).await?;

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
async fn zellij_list_sessions(ssh_addr: &str) -> Result<(Vec<Zesh>, String)> {
    println!("Attempting to contact remote...");
    let ssh = Session::connect(ssh_addr, KnownHosts::Strict).await?;
    println!("Connection established");

    println!("Checking for zellij executable on remote PATH...");
    let output = ssh.command("which").arg("zellij").output().await?;
    if output.stdout.is_empty() {
        let err = "Remote does not have Zellij in PATH. Aborting.";
        eprintln!("{err}");
        return Err(anyhow!(err));
    }

    let zellij_out = ssh
        .command("zellij")
        .arg("ls")
        .arg("-n") // no ansi escapes
        .output()
        .await?;
    let stdout = String::from_utf8(zellij_out.stdout)?;
    let stderr = String::from_utf8(zellij_out.stderr)?;
    println!("{stderr}");

    if stderr.contains("No active zellij sessions found.") {
        return Ok((vec![], stdout));
    }

    if stdout.is_empty() {
        let err = "Command `zellij ls` failed on remote. Aborting.";
        eprintln!("{err}");
        return Err(anyhow!(err));
    }

    let zs = stdout.trim().split('\n').flat_map(Zesh::try_from).collect();

    let zs_raw = stdout
        .lines()
        .enumerate()
        .fold(String::new(), |mut output, (i, l)| {
            let _ = writeln!(output, "{i} {}", l);
            output
        });

    ssh.close().await?;
    Ok((zs, zs_raw))
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

const MAX_IPV6_LENGTH: usize = 45;

const V4: &str =
    r#"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}"#;

fn v6() -> &'static str {
    static PATTERN: OnceLock<String> = OnceLock::new();
    PATTERN.get_or_init(|| {
        const V6_SEG: &str = r#"[a-fA-F\d]{1,4}"#;
        #[rustfmt::skip]
        let buf = [
            "(?:", 
            "(?:", V6_SEG, ":){7}(?:", V6_SEG, "|:)|",                                            // 1:2:3:4:5:6:7::  1:2:3:4:5:6:7:8
            "(?:", V6_SEG, ":){6}(?:", V4, "|:", V6_SEG, "|:)|",                                  // 1:2:3:4:5:6::    1:2:3:4:5:6::8   1:2:3:4:5:6::8  1:2:3:4:5:6::1.2.3.4
            "(?:", V6_SEG, ":){5}(?::", V4, "|(?::", V6_SEG, "){1,2}|:)|",                        // 1:2:3:4:5::      1:2:3:4:5::7:8   1:2:3:4:5::8    1:2:3:4:5::7:1.2.3.4
            "(?:", V6_SEG, ":){4}(?:(?::", V6_SEG, "){0,1}:", V4, "|(?::", V6_SEG, "){1,3}|:)|",  // 1:2:3:4::        1:2:3:4::6:7:8   1:2:3:4::8      1:2:3:4::6:7:1.2.3.4
            "(?:", V6_SEG, ":){3}(?:(?::", V6_SEG, "){0,2}:", V4, "|(?::", V6_SEG, "){1,4}|:)|",  // 1:2:3::          1:2:3::5:6:7:8   1:2:3::8        1:2:3::5:6:7:1.2.3.4
            "(?:", V6_SEG, ":){2}(?:(?::", V6_SEG, "){0,3}:", V4, "|(?::", V6_SEG, "){1,5}|:)|",  // 1:2::            1:2::4:5:6:7:8   1:2::8          1:2::4:5:6:7:1.2.3.4
            "(?:", V6_SEG, ":){1}(?:(?::", V6_SEG, "){0,4}:", V4, "|(?::", V6_SEG, "){1,6}|:)|",  // 1::              1::3:4:5:6:7:8   1::8            1::3:4:5:6:7:1.2.3.4
            "(?::(?:(?::", V6_SEG, "){0,5}:", V4, "|(?::", V6_SEG, "){1,7}|:))",                  // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8  ::8             ::1.2.3.4
            ")(?:%[0-9a-zA-Z]{1,})?"                                                              // %eth0            %1
        ];
        buf.join("").to_owned()
    })
}

fn ip_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(format!("(?:^{}$)|(?:^{}$)", V4, v6()).as_str()).unwrap())
}

/// Check if `string` is IPv6 or IPv4.
pub fn is_ip(string: &str) -> bool {
    if string.len() > MAX_IPV6_LENGTH {
        return false;
    }

    ip_regex().is_match(string)
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

    const TEST_V4: [&str; 16] = [
        "0.0.0.0",
        "8.8.8.8",
        "127.0.0.1",
        "100.100.100.100",
        "192.168.0.1",
        "18.101.25.153",
        "123.23.34.2",
        "172.26.168.134",
        "212.58.241.131",
        "128.0.0.0",
        "23.71.254.72",
        "223.255.255.255",
        "192.0.2.235",
        "99.198.122.146",
        "46.51.197.88",
        "173.194.34.134",
    ];

    const TEST_V4NOT: [&str; 10] = [
        ".100.100.100.100",
        "100..100.100.100.",
        "100.100.100.100.",
        "999.999.999.999",
        "256.256.256.256",
        "256.100.100.100.100",
        "123.123.123",
        "http://123.123.123",
        "1000.2.3.4",
        "999.2.3.4",
    ];

    const TEST_V6: [&str; 128] = [
        "::",
        "1::",
        "::1",
        "1::8",
        "1::7:8",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6::8",
        "1:2:3:4:5:6:7::",
        "1:2:3:4:5::7:8",
        "1:2:3:4:5::8",
        "1:2:3::8",
        "1::4:5:6:7:8",
        "1::6:7:8",
        "1::3:4:5:6:7:8",
        "1:2:3:4::6:7:8",
        "1:2::4:5:6:7:8",
        "::2:3:4:5:6:7:8",
        "1:2::8",
        "2001:0000:1234:0000:0000:C1C0:ABCD:0876",
        "3ffe:0b00:0000:0000:0001:0000:0000:000a",
        "FF02:0000:0000:0000:0000:0000:0000:0001",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "0000:0000:0000:0000:0000:0000:0000:0000",
        "::ffff:192.168.1.26",
        "2::10",
        "ff02::1",
        "fe80::",
        "2002::",
        "2001:db8::",
        "2001:0db8:1234::",
        "::ffff:0:0",
        "::ffff:192.168.1.1",
        "1:2:3:4::8",
        "1::2:3:4:5:6:7",
        "1::2:3:4:5:6",
        "1::2:3:4:5",
        "1::2:3:4",
        "1::2:3",
        "::2:3:4:5:6:7",
        "::2:3:4:5:6",
        "::2:3:4:5",
        "::2:3:4",
        "::2:3",
        "::8",
        "1:2:3:4:5:6::",
        "1:2:3:4:5::",
        "1:2:3:4::",
        "1:2:3::",
        "1:2::",
        "1:2:3:4::7:8",
        "1:2:3::7:8",
        "1:2::7:8",
        "1:2:3:4:5:6:1.2.3.4",
        "1:2:3:4:5::1.2.3.4",
        "1:2:3:4::1.2.3.4",
        "1:2:3::1.2.3.4",
        "1:2::1.2.3.4",
        "1::1.2.3.4",
        "1:2:3:4::5:1.2.3.4",
        "1:2:3::5:1.2.3.4",
        "1:2::5:1.2.3.4",
        "1::5:1.2.3.4",
        "1::5:11.22.33.44",
        "fe80::217:f2ff:254.7.237.98",
        "fe80::217:f2ff:fe07:ed62",
        "2001:DB8:0:0:8:800:200C:417A",
        "FF01:0:0:0:0:0:0:101",
        "0:0:0:0:0:0:0:1",
        "0:0:0:0:0:0:0:0",
        "2001:DB8::8:800:200C:417A",
        "FF01::101",
        "0:0:0:0:0:0:13.1.68.3",
        "0:0:0:0:0:FFFF:129.144.52.38",
        "::13.1.68.3",
        "::FFFF:129.144.52.38",
        "fe80:0000:0000:0000:0204:61ff:fe9d:f156",
        "fe80:0:0:0:204:61ff:fe9d:f156",
        "fe80::204:61ff:fe9d:f156",
        "fe80:0:0:0:204:61ff:254.157.241.86",
        "fe80::204:61ff:254.157.241.86",
        "fe80::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "2001:db8:85a3::8a2e:370:7334",
        "2001:0db8:0000:0000:0000:0000:1428:57ab",
        "2001:0db8:0000:0000:0000::1428:57ab",
        "2001:0db8:0:0:0:0:1428:57ab",
        "2001:0db8:0:0::1428:57ab",
        "2001:0db8::1428:57ab",
        "2001:db8::1428:57ab",
        "::ffff:12.34.56.78",
        "::ffff:0c22:384e",
        "2001:0db8:1234:0000:0000:0000:0000:0000",
        "2001:0db8:1234:ffff:ffff:ffff:ffff:ffff",
        "2001:db8:a::123",
        "::ffff:192.0.2.128",
        "::ffff:c000:280",
        "a:b:c:d:e:f:f1:f2",
        "a:b:c::d:e:f:f1",
        "a:b:c::d:e:f",
        "a:b:c::d:e",
        "a:b:c::d",
        "::a",
        "::a:b:c",
        "::a:b:c:d:e:f:f1",
        "a::",
        "a:b:c::",
        "a:b:c:d:e:f:f1::",
        "a:bb:ccc:dddd:000e:00f:0f::",
        "0:a:0:a:0:0:0:a",
        "0:a:0:0:a:0:0:a",
        "2001:db8:1:1:1:1:0:0",
        "2001:db8:1:1:1:0:0:0",
        "2001:db8:1:1:0:0:0:0",
        "2001:db8:1:0:0:0:0:0",
        "2001:db8:0:0:0:0:0:0",
        "2001:0:0:0:0:0:0:0",
        "A:BB:CCC:DDDD:000E:00F:0F::",
        "0:0:0:0:0:0:0:a",
        "0:0:0:0:a:0:0:0",
        "0:0:0:a:0:0:0:0",
        "a:0:0:a:0:0:a:a",
        "a:0:0:a:0:0:0:a",
        "a:0:0:0:a:0:0:a",
        "a:0:0:0:a:0:0:0",
        "a:0:0:0:0:0:0:0",
        "fe80::7:8%eth0",
        "fe80::7:8%1",
    ];

    const TEST_V6NOT: [&str; 96] = [
        "",
        "1:",
        ":1",
        "11:36:12",
        "02001:0000:1234:0000:0000:C1C0:ABCD:0876",
        "2001:0000:1234:0000:00001:C1C0:ABCD:0876",
        "2001:0000:1234: 0000:0000:C1C0:ABCD:0876",
        "2001:1:1:1:1:1:255Z255X255Y255",
        "3ffe:0b00:0000:0001:0000:0000:000a",
        "FF02:0000:0000:0000:0000:0000:0000:0000:0001",
        "3ffe:b00::1::a",
        "::1111:2222:3333:4444:5555:6666::",
        "1:2:3::4:5::7:8",
        "12345::6:7:8",
        "1::5:400.2.3.4",
        "1::5:260.2.3.4",
        "1::5:256.2.3.4",
        "1::5:1.256.3.4",
        "1::5:1.2.256.4",
        "1::5:1.2.3.256",
        "1::5:300.2.3.4",
        "1::5:1.300.3.4",
        "1::5:1.2.300.4",
        "1::5:1.2.3.300",
        "1::5:900.2.3.4",
        "1::5:1.900.3.4",
        "1::5:1.2.900.4",
        "1::5:1.2.3.900",
        "1::5:300.300.300.300",
        "1::5:3000.30.30.30",
        "1::400.2.3.4",
        "1::260.2.3.4",
        "1::256.2.3.4",
        "1::1.256.3.4",
        "1::1.2.256.4",
        "1::1.2.3.256",
        "1::300.2.3.4",
        "1::1.300.3.4",
        "1::1.2.300.4",
        "1::1.2.3.300",
        "1::900.2.3.4",
        "1::1.900.3.4",
        "1::1.2.900.4",
        "1::1.2.3.900",
        "1::300.300.300.300",
        "1::3000.30.30.30",
        "::400.2.3.4",
        "::260.2.3.4",
        "::256.2.3.4",
        "::1.256.3.4",
        "::1.2.256.4",
        "::1.2.3.256",
        "::300.2.3.4",
        "::1.300.3.4",
        "::1.2.300.4",
        "::1.2.3.300",
        "::900.2.3.4",
        "::1.900.3.4",
        "::1.2.900.4",
        "::1.2.3.900",
        "::300.300.300.300",
        "::3000.30.30.30",
        "2001:DB8:0:0:8:800:200C:417A:221",
        "FF01::101::2",
        "1111:2222:3333:4444::5555:",
        "1111:2222:3333::5555:",
        "1111:2222::5555:",
        "1111::5555:",
        "::5555:",
        ":::",
        "1111:",
        ":",
        ":1111:2222:3333:4444::5555",
        ":1111:2222:3333::5555",
        ":1111:2222::5555",
        ":1111::5555",
        ":::5555",
        "1.2.3.4:1111:2222:3333:4444::5555",
        "1.2.3.4:1111:2222:3333::5555",
        "1.2.3.4:1111:2222::5555",
        "1.2.3.4:1111::5555",
        "1.2.3.4::5555",
        "1.2.3.4::",
        "fe80:0000:0000:0000:0204:61ff:254.157.241.086",
        "123",
        "ldkfj",
        "2001::FFD3::57ab",
        "2001:db8:85a3::8a2e:37023:7334",
        "2001:db8:85a3::8a2e:370k:7334",
        "1:2:3:4:5:6:7:8:9",
        "1::2::3",
        "1:::3:4:5",
        "1:2:3::4:5:6:7:8:9",
        "::ffff:2.3.4",
        "::ffff:257.1.2.3",
        "::ffff:12345678901234567890.1.26",
    ];

    #[test]
    fn test_ip_regex() {
        for fixture in TEST_V4 {
            assert!(ip_regex().is_match(fixture));
        }

        for fixture in TEST_V4NOT {
            assert!(!ip_regex().is_match(fixture));
        }

        for fixture in TEST_V6 {
            assert!(ip_regex().is_match(fixture));
        }

        for fixture in TEST_V6NOT {
            assert!(!ip_regex().is_match(fixture));
        }
    }

    #[test]
    fn test_ip() {
        assert!(is_ip("192.168.0.1"));
        assert!(is_ip("1:2:3:4:5:6:7:8"));
        assert!(is_ip("::1"));
        assert!(is_ip("2001:0dc5:72a3:0000:0000:802e:3370:73E4"));
    }
}
