use crate::{
    logger,
    scans::{nmap_scan::NmapScan, scan::ScanTrait},
};
use std::path::PathBuf;

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Scanning {}", target));
    let mut nmap_scan = NmapScan::new(output_dir);
    let res = nmap_scan.start(&target);
    if !res {
        logger::print_err("Nmap did not run");
    } else {
        nmap_scan.parse_output();
        nmap_scan.print_results();
    }
}
