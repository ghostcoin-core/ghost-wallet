//! `seal-release-key`: makes the Seal's release key on an offline machine,
//! signs measurement lists with it and checks signed lists. See the crate
//! notes and `enclave/RUNBOOK.md`.

use std::process::ExitCode;

use seal_release_key::{Command, USAGE, keygen, parse_args, sign_file, verify_file};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(why) => {
            eprintln!("seal-release-key: {why}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let done = match command {
        Command::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        // Only the public half goes to stdout, and nothing else to either.
        Command::Keygen { out } => keygen(&out).map(|public_hex| public_hex + "\n"),
        Command::Sign { list, key, out, force } => sign_file(&list, &key, &out, force)
            .map(|builds| format!("ok: signed {builds} builds into {}\n", out.display())),
        Command::Verify { list, public } => verify_file(&list, &public)
            .map(|builds| format!("ok: the list's {builds} builds are signed by this release key\n")),
    };
    match done {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("seal-release-key: {why}");
            ExitCode::FAILURE
        }
    }
}
