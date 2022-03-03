use colored::Colorize;
use std::{
    env,
    fs::{create_dir, remove_dir_all},
    io,
    path::PathBuf,
    process::exit,
};
use url::{Host, ParseError};
use which::which;
mod engine;
mod logger;
mod scans;
/**

So what we're doing is I'm creating a struct with all Scantypes in them. Nmap, Feroxbuster, etc.

The first thing to run is always Nmap, and after that fire the triggers that are configured for the other scantypes. This means that a scantype can have triggers.
These triggers are typically ports that are discovered to be open. If a scantype does not find any output, the triggers are not triggered anymore.

*/

fn main() {
    print_banner();
    let args: Vec<String> = env::args().collect();
    //Not enough args. This will probably be replaced by code to configure the 'Clap' crate.
    if args.len() < 2 {
        terminate("No target provided. Usage: tartaros <ip|hostname>");
    }

    //We exit if the target can not be parsed to a valid Host.
    if let Ok(target) = parse_target(&args[1]) {
        if !nmap_is_installed() {
            //Nmap is required for this program to even run. If it's not installed, exit.
            terminate(
                "Nmap is not installed, but it is required. Install it with: sudo apt install nmap",
            );
        } else {
            if let Ok(output_dir) = create_output_dir() {
                engine::run(target, output_dir.clone());
                // if let Err(_) = remove_dir_all(output_dir){
                //     terminate("Unable to delete the temporary output directory '.tartaros_temp'. Please try to do so manually.");
                // }
            } else {
                terminate("Unable to create an output directory for storing intermediate results. Please change your working directory or run this program as a high-privileged user.");
            }
        }
    }
}

/// Parses the target to a Host.
pub fn parse_target(target_raw: &str) -> Result<String, ParseError> {
    let target = Host::parse(target_raw)?;
    Ok(target.to_string())
}

/// Checks whether Nmap is installed by using 'which'.
fn nmap_is_installed() -> bool {
    if let Ok(_) = which("nmap") {
        return true;
    }

    false
}

/// Attempts to create a directory '.tartaros_temp' in the current working directory for storing intermediate results of the separate scans that run.
fn create_output_dir() -> Result<PathBuf, io::Error> {
    let path = PathBuf::from(".tartaros_temp");
    //If there was an error when trying to create the directory (due to existence), attempt to remove it and create it again.
    if let Err(_) = create_dir(&path) {
        remove_dir_all(&path)?;
        create_dir(&path)?;
    }

    Ok(path)
}

/// Deletes any remaining files, outputs an error message and terminates the process.
fn terminate(msg: &str) {
    logger::print_err(&format!("Error: {}", msg));
    exit(1);
}

fn print_banner() {
    // let hand = "
    //                      ......        ...
    //                      ...*/...    ...*...
    //              ......    ...(....   ...(...
    //             ....(....   ....(...   ../*..
    //               ....(....   ...(...  ...(...
    //         ......  ...,(... ...(... ...*(...
    //        ....(.... ...(,.. ..,(......((...
    //          .../(....................,(((
    //            ..**...../////////////(((......
    //            ...////////(((((((((((((,..(((...
    //            ...///((((((((((,*(((,,,,...((%...
    //            ...//(((.........*(.........((%...
    //            ...//((((((((((((.../(((((((%(....
    //             ...//((((((((((((((((((((%....
    //              ......((((((((((((.........
    //                ...,/////(((((((,.....
    //                ...////////(((((%%...
    //           ......../////////((((%%..."
    //     .green();
    // println!("{}", &hand);
    // println!(
    //     "{}{}{}",
    //     "              ........".truecolor(205, 133, 63),
    //     "/////////((((%%".green(),
    //     ".../,...........".truecolor(205, 133, 63)
    // );
    // println!(
    //     "{}{}{}",
    //     "       .........*//...".truecolor(205, 133, 63),
    //     "/////////((((%%".green(),
    //     "...//............".truecolor(205, 133, 63)
    // );
    // println!(
    //     "{}{}{}",
    //     "        ......********".truecolor(205, 133, 63),
    //     "//////////((((%%".green(),
    //     "...****.....".truecolor(205, 133, 63)
    // );
    // println!(
    //     "{}",
    //     "            .....................................".truecolor(205, 133, 63)
    // );
    let text = "
▄▄▄█████▓ ▄▄▄       ██▀███  ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████    ██████
▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▒██    ▒
▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄
░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░  ▒   ██▒
  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░▒██████▒▒
  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
    ░      ▒   ▒▒ ░  ░▒ ░ ▒░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░
  ░        ░   ▒     ░░   ░   ░        ░   ▒     ░░   ░ ░ ░ ░ ▒  ░  ░  ░
               ░  ░   ░                    ░  ░   ░         ░ ░        ░  "
        .bright_green();
    println!("{}", text);
}
