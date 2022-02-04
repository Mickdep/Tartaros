use colored::Colorize;
use core::num::dec2flt::parse;
use std::{
    env,
    fmt::format,
    path::{Path, PathBuf},
    process::exit, fs::create_dir,
};
use url::{Host, ParseError};
use which::which;
mod engine;
mod logger;
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
          if let Ok(res) = create_dir(){
            engine::run(target);
            
          }else{
            terminate("Unable to create an output directory for storing intermediate results. Please change your working directory or run this program as a high-privileged user.");
          }
        }
    }
}

pub fn parse_target(target_raw: &str) -> Result<String, ParseError> {
    let target = Host::parse(target_raw)?;
    Ok(target.to_string())
}

fn nmap_is_installed() -> bool {
    if let Ok(_) = which("nmap") {
        return true;
    }

    false
}

fn create_output_dir() -> std::io::Result<()> {
    if let Ok(mut path) = env::current_dir() {
        path.push(output_file);
        arg_collection.file = path;
    } else {
        return Err("Could not resolve valid file path");
    }

    false
}

fn terminate(msg: &str) {
    logger::print_err(&format!("Error: {}", msg));
    exit(1);
}

fn print_banner() {
    let hand = "
                         ......        ...
                         ...*/...    ...*...
                 ......    ...(....   ...(...
                ....(....   ....(...   ../*..
                  ....(....   ...(...  ...(...
            ......  ...,(... ...(... ...*(...
           ....(.... ...(,.. ..,(......((...
             .../(....................,(((
               ..**...../////////////(((......
               ...////////(((((((((((((,..(((...
               ...///((((((((((,*(((,,,,...((%...
               ...//(((.........*(.........((%...
               ...//((((((((((((.../(((((((%(....
                ...//((((((((((((((((((((%....
                 ......((((((((((((.........
                   ...,/////(((((((,.....
                   ...////////(((((%%...
              ......../////////((((%%..."
        .green();
    println!("{}", &hand);
    println!(
        "{}{}{}",
        "              ........".truecolor(205, 133, 63),
        "/////////((((%%".green(),
        ".../,...........".truecolor(205, 133, 63)
    );
    println!(
        "{}{}{}",
        "       .........*//...".truecolor(205, 133, 63),
        "/////////((((%%".green(),
        "...//............".truecolor(205, 133, 63)
    );
    println!(
        "{}{}{}",
        "        ......********".truecolor(205, 133, 63),
        "//////////((((%%".green(),
        "...****.....".truecolor(205, 133, 63)
    );
    println!(
        "{}",
        "            .....................................".truecolor(205, 133, 63)
    );
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
        .green();
    println!("{}", text);
}
