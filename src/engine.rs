use crate::{
    logger,
    scans::{error::ScanError, nmap::NmapScan, scan::Scan},
};
use std::{collections::HashMap, path::PathBuf};

pub struct ScanTriggers {
    pub triggers: HashMap<String, ()>,
}

impl ScanTriggers {
    pub fn new() -> ScanTriggers {
        ScanTriggers {
            triggers: HashMap::from([
                (String::from("80"), port80()),
                (String::from("445"), port445()),
            ]),
        }
    }
}

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));
    let scan_triggers = ScanTriggers::new();

    let nmap_scan = NmapScan::new(output_dir, target);
    match nmap_scan.run() {
        Err(err) => match err {
            ScanError::NotInstalled => logger::print_err("Nmap is not installed."),
            ScanError::Runtime => logger::print_err("Encountered runtime error"),
            ScanError::None => logger::print_err("None"),
        },

        Ok(results) => {
            if results.len() < 1 {
                logger::print_warn("Nmap found no open ports. Shutting down.");
            } else {
                println!("");
                println!("");
                logger::print_ok("Triggering other scans now...");

                //Some of the follow-up scans can be run in parallel.
                //I will add multithreading when most of the basic functionality has been implemented.
                results
                    .iter()
                    // .filter(|x| matches!(x.port.state, PortState::Open))
                    .for_each(|result| {
                        if scan_triggers.triggers.contains_key(&result.port.num) {
                            scan_triggers.triggers[&result.port.num]
                        }
                    });
                // for result in results {
                //     scan_triggers.triggers[result.port.num.as_str()];
                // }
            }
        }
    }
}

fn port80() {
    logger::print_warn("Running Feroxbuster, Micrawl, chrome_headless_for_screenshots");
}

fn port445() {
    logger::print_warn("Running smbclient, smb nmap scan, etc.");
}
