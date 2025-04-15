use std::process::Command;

use crate::{Args, ip::is_ip};
use ansi_term::Color;
use indoc::{eprintdoc, formatdoc};

pub fn args_are_valid(args: &Args) -> bool {
    let error = Color::Red.paint("error: ");
    let usage_lbl = Color::White.bold().underline().paint("Usage");
    let exe = Color::White.bold().paint("ssh_zellij");
    let help = Color::White.bold().paint("--help");
    let usr = Color::Red.paint("<user>");
    let at = Color::Red.paint("@");
    let i = Color::Red.paint("<ip>");
    let addr = Color::White.bold().paint(args.ssh_addr.clone());
    let usage = formatdoc! {"
    {usage_lbl}: {exe} <SSH_ADDR>

    For more information, try '{help}'"
    };

    let Some((user, ip)) = args.ssh_addr.split_once("@") else {
        eprintdoc! {
        "
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

pub fn env_is_valid() -> bool {
    let has_fzf = !Command::new("which")
        .arg("fzf")
        .output()
        .expect("Failed to check for fzf")
        .stdout
        .is_empty();

    if !has_fzf {
        let msg =
            "Failed to find fzf executable on PATH. Ensure fzf is executable to use this program";
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
