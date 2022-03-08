use crate::{
    logger,
    scans::{nmap::{NmapScan, self}, scan::Scan, error::ScanError},
};
use std::path::PathBuf;

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));

    //First run Nmap
    let nmap_scan = NmapScan::new(output_dir, target);
    if let Err(err) = nmap_scan.run() {
        match err {
            ScanError::NotInstalled => logger::print_err("Nmap is not installed."),
            ScanError::Runtime => logger::print_err("Encountered runtime error"),
            ScanError::None => logger::print_err("None"),
        }
    }
    let results = nmap_scan.run().unwrap(); //We know that Nmap will run here because the installation check has been performed in main.rs already.
    if results.len() < 1 {
        logger::print_err("Nmap found no open ports");
    } else {
        println!("");
        println!("");
        logger::print_ok("Triggering other scans now...");

        //Some of the follow-up scans can be run in parallel.
        //I will add multithreading when most of the basic functionality has been implemented.
        for result in results{
            match result.port.num.as_str() {
                "80" => logger::print_warn("Running Feroxbuster, Micrawl, chrome_headless_for_screenshots"),
                "445" => logger::print_warn("Running smbclient, enum4linux, ldapsearch"),
                "21" => logger::print_warn("Running ftp scan"),
                _ => {}
            }
        }
    }
}
