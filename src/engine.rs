use crate::{
    logger,
    scans::{
        error::ScanError,
        feroxbuster::FeroxbusterScan,
        nmap::{self, NmapScan, PortState},
        scan::Scan, nuclei::NucleiScan,
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
                (String::from("445"), port445_triggers as fn(PathBuf, String)),
            ]),
        }
    }
}

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));
    logger::print_ok("NOTE: Most scans (if they offer the option) will output their raw results to a file in the output directory.\n\n");
    let scan_triggers = ScanTriggers::new();
    port80_triggers(output_dir, target);
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

    //             //Some of the follow-up scans can be run in parallel.
    //             //I will add multithreading when most of the basic functionality has been implemented.
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

//The functions below will need the target, as well as the output directory (i guess).
//All the scans below can (mostly) be run in parallel.
fn port80_triggers(output_dir: PathBuf, target: String) {
    /*TORUN:
    1. Feroxbuster
    2. Micrawl (compare this with feroxbuster and deduplicate the results)
    3. Check the results of the previous two scans. If 'wp-admin' is present (or anything indicating wordpress), run WPScan.
    4. [OPTIONAL] Check the results of the previous two scans. If there are url's that ferobuster found that Micrawl did NOT find, take screenshots with chrome headless.
    5. Nuclei (?)
    7. Something like crt.sh or sublister (although this might not be specific to port 80)
    8. CVE scan (could used Nmap scripts here)
    */

    // let feroxbuster_scan = FeroxbusterScan::new(output_dir.clone(), target.clone());
    // if let Ok(res) = feroxbuster_scan.run() {
    //     println!("Worked");
    // }else{
    //     println!("Did not work");
    // }
    
    let nuclei_scan = NucleiScan::new(output_dir, target);
    if let Ok(res) = nuclei_scan.run() {
        println!("Worked as well");
    }else{
        println!("Did not work.");
    }
}

//Tbh could use a lot of Nmap's scripting capabilities here already.
fn port445_triggers(output_dir: PathBuf, target: String) {
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
