use crate::{
    logger,
    scans::{nmap_scan::NmapScan, scan::ScanTrait},
};
use std::path::PathBuf;

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));

    //First run Nmap
    let mut nmap_scan = NmapScan::new(output_dir);
    nmap_scan.run(&target);
    nmap_scan.parse_output();
    nmap_scan.print_results();
    if nmap_scan.scan_results.is_empty() {
        logger::print_err("Nmap did not run");
    }
}
