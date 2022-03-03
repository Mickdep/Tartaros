use crate::{
    logger,
    scans::{nmap_scan::NmapScan, scan::ScanTrait},
};
use std::path::PathBuf;

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));

    //First run Nmap
    let nmap_scan = NmapScan::new(output_dir, target);
    let results = nmap_scan.run();
    if results.len() < 1 {
        logger::print_err("Nmap found no open ports");
    } else {
        println!("");
        println!("");
        logger::print_ok("Triggering other scans now...");

        for result in results{
            match result.port.num.as_str() {
                "80" => logger::print_warn("Running Feroxbuster, Micrawl, Screenshooter"),
                "445" => logger::print_warn("Running smbclient, enum4linux, ldapsearch"),
                "21" => logger::print_warn("Running ftp scan"),
                _ => {}
            }
        }
    }
    // nmap_scan.run(&target);
    // nmap_scan.parse_output();
    // nmap_scan.print_results();
    // if nmap_scan.scan_results.is_empty() {
    //     logger::print_err("Nmap did not run");
    // }
}
