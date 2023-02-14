use colored::Colorize;
use std::{
    env,
    fs::{create_dir, create_dir_all, remove_dir_all},
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
        terminate("No target provided. Usage: tartaros <ip|hostname> (make sure you DON'T specify a protocol such as http://*)");
    }

    //We exit if the target can not be parsed to a valid Host.
    if let Ok(target) = parse_target(&args[1]) {
        if !nmap_is_installed() {
            //Nmap is required for this program to run. If it's not installed, exit.
            terminate(
                "Nmap is not installed, but it is required. Install it with: sudo apt install nmap",
            );
        } else {
            if let Ok(output_dir) = create_output_dir(&target) {
                engine::run(target, output_dir);
                // if let Err(_) = remove_dir_all(output_dir){
                //     terminate("Unable to delete the temporary output directory '.tartaros_temp'. Please try to do so manually.");
                // }
            } else {
                terminate("Unable to create an output directory for storing results. Please change your working directory or run this program as a high-privileged user.");
            }
        }
    } else {
        terminate("Unable to parse target string. Please make sure that you're not using any protocol specifiers (such as 'http://').")
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

/// Attempts to create a directory 'tartaros_results_{target}' in the current working directory for storing intermediate results of the separate scans that run.
fn create_output_dir(target: &str) -> Result<PathBuf, io::Error> {
    let home_dir = std::env::var("HOME").unwrap(); //Is always set as env variable because it's required by the POSIX spec (https://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap08.html)
    let path = PathBuf::from(home_dir).join("tartaros").join(target);
    if let Err(_) = create_dir_all(&path) {
        remove_dir_all(&path)?;
        create_dir_all(&path)?;
    }

    //Should always be a valid path since we return early if creation fails.
    Ok(path)
}

/// Outputs an error message and terminates the process.
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
              ......../////////((((%%...".bright_green();
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
        .bright_green();
    println!("{}", text);
}
