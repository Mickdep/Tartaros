use std::path::PathBuf;
use crate::logger;

pub fn run(target: String, output_dir: PathBuf) {
    logger::print_ok(&format!("Running engine for target '{}' with output_dir {:?}", target, output_dir));
    //Requires String here because the engine needs to take owernship of it. Passing it to the other scans can then be done through references since they only need it once.
}