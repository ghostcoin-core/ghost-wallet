//! `seal-setup`: sets up one Ghost test card on the reader with the dev test
//! Seal's keys and records it in the card registry. See the crate notes.

use std::process::ExitCode;

use seal_setup::{Options, Refusal, USAGE, parse_args};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_args(&args) {
        Ok(options) => options,
        Err(Refusal::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(Refusal::Usage(why)) => {
            eprintln!("seal-setup: {why}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match set_up_on_reader(&options) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("seal-setup: {why}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "pcsc-reader")]
fn set_up_on_reader(options: &Options) -> Result<String, String> {
    use ghost_seal::{Clock, SystemClock, SystemRandom};
    use seal_setup::reader::PcscCard;

    let mut card = PcscCard::connect(options.reader.as_deref())?;
    let uid = card.uid()?;
    let report = seal_setup::run_setup(&mut card, uid, options, SystemClock.now_unix(), &mut SystemRandom)
        .map_err(|e| format!("{}: refused: {e}", seal_setup::uid_hex(&uid)))?;
    Ok(seal_setup::describe(&uid, &report))
}

#[cfg(not(feature = "pcsc-reader"))]
fn set_up_on_reader(_options: &Options) -> Result<String, String> {
    Err("this build has no card reader: build it with `--features pcsc-reader` on the Mac Studio".to_owned())
}
