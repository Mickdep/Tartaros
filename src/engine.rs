use crate::{
    logger,
    scans::{nmap_scan::NmapScan, scan::ScanTrait},
};
use std::path::PathBuf;

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!(
        "Running engine for target '{}' with output_dir {:?}",
        target, output_dir
    ));
    let nmap_scan = NmapScan::new(output_dir);
    let res = nmap_scan.start(&target);
    if !res {
        logger::print_err("Nmap did not run");
    } else {
        logger::print_ok("Nmap successfully finished execution");
        nmap_scan.parse_output();
    }
}
