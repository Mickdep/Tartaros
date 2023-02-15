use crate::{
    logger,
    scans::{
        error::ScanError,
        feroxbuster::FeroxbusterScan,
        nmap::{self, NmapScan, PortState},
        nuclei::NucleiScan,
        scan::Scan,
    },
};
use std::{collections::HashMap, path::PathBuf};

pub struct ScanTriggers {
    ///HashMap that maps Strings to function pointers. Allows looking up a port number and triggering the appropriate function.
    pub triggers: HashMap<String, fn(PathBuf, String)>,
}

impl ScanTriggers {
    pub fn new() -> ScanTriggers {
        ScanTriggers {
            triggers: HashMap::from([
                (String::from("80"), port80_triggers as fn(PathBuf, String)),
                (String::from("443"), port443_triggers as fn(PathBuf, String)),
                (String::from("445"), port445_triggers as fn(PathBuf, String)),
            ]),
        }
    }
}

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));
    logger::print_ok("NOTE: Most scans (if they offer the option) will output their raw results to a file in the output directory.\n\n");
    let scan_triggers = ScanTriggers::new();
    always_triggers(output_dir.clone(), target.clone());
    // let nmap_scan = NmapScan::new(output_dir.clone(), target.clone());
    // match nmap_scan.run() {
    //     //This error handling is very much experimental at this point. Should be worked out and be more elaborate in the future.
    //     Err(err) => handle_scan_error(err),
    //     Ok(results) => {
    //         if results.len() < 1 {
    //             //TODO: Add option to enable -Pn option for Nmap to assume that the host is up. Maybe even enable this by default...
    //             logger::print_warn("NOTE: Nmap did not find any open ports. This is weird and should be investigated manually if you expect the host to be up. Terminating.");
    //         } else {
    //             println!("");
    //             //Nmap scan was successful and found open ports. Now run the "always trigger" scans.
    //             always_triggers(output_dir.clone(), target.clone());
    //             results
    //                 .iter()
    //                 .filter(|x| matches!(x.port.state, PortState::Open)) // Make sure that the port is actually open
    //                 .for_each(|result| {
    //                     if scan_triggers.triggers.contains_key(&result.port.num) {
    //                         scan_triggers.triggers[&result.port.num](
    //                             output_dir.clone(),
    //                             target.clone(),
    //                         ); //Trigger the other scan based on the port number
    //                     }
    //                 });
    //         }
    //     }
    // }
}

//Scans that are always triggered, regardless of port.
fn always_triggers(output_dir: PathBuf, target: String) {

    //NUCLEI
    //After this scan I want to automatically report all the missing HTTP headers.
    //I can loop through the result, check whether the missing header should be reported, and if so:
    //Copy the curl command, perform it, save the output, and mark the command.
    let nuclei_scan = NucleiScan::new(output_dir, target);
    if let Err(err) = nuclei_scan.run() {
        handle_scan_error(err)
    }

    //CVE scan
    //nmap -sC --script cve*
}
fn port80_triggers(output_dir: PathBuf, target: String) {

    //FEROXBUSTER
    let feroxbuster_scan = FeroxbusterScan::new(output_dir.clone(), target.clone(), 80);
    if let Err(err) = feroxbuster_scan.run() {
        handle_scan_error(err);
    }
}

fn port443_triggers(output_dir: PathBuf, target: String) {
    //Only perform an initial feroxbuster scan, since this can really differ per port.
    //FEROXBUSTER
    let feroxbuster_scan = FeroxbusterScan::new(output_dir.clone(), target.clone(), 443);
    if let Err(err) = feroxbuster_scan.run() {
        handle_scan_error(err);
    }

    //NMAP SSL SCAN
    //This scan will perform an SSL scan of the target and automatically report the following findings:
    // - Weak ciphers
    // - TLS 1.0 and/or TLS 1.1
    // - Self-signed/untrusted certificate
    // I also want to do this for port 3389
}

//Tbh could use a lot of Nmap's scripting capabilities here already.
fn port445_triggers(output_dir: PathBuf, target: String) {
    //Run Nmap scan nmap -sC --scrip smb*
    logger::print_warn("Running smbclient, smb nmap scan, etc.");
}

fn handle_scan_error(err: ScanError) {
    match err {
        ScanError::NotInstalled(scan) => {
            logger::print_err(&format!("{}: Not installed, skipping this scan.", scan))
        }
        ScanError::Runtime(scan) => {
            logger::print_err(&format!("{}: Ecountered runtime error", scan))
        }
        _ => {}
    }
}
