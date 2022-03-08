use std::path::PathBuf;

use url::Url;

use crate::logger;
use which::which;
use super::{scan::Scan, error::ScanError};

pub struct FeroxbusterScan {
    output_file: PathBuf,
    scan_args: Vec<String>
}

pub struct FeroxbusterScanResult {
    pub url: Url,
    pub response_code: String,
    pub response_size: String
}

impl FeroxbusterScan {
    pub fn new(mut output_dir: PathBuf, target: String) -> FeroxbusterScan {
        output_dir.push("feroxbuster");
        FeroxbusterScan {
            output_file: output_dir,
            scan_args: vec![String::from("Some args")]
        }
    }
}

impl Scan for FeroxbusterScan {
    type ScanResult = FeroxbusterScanResult;

    fn run(&self) -> Result<Vec<Self::ScanResult>, ScanError> {
        if let Err(_) = which("feroxbuster") {
            logger::print_err("Feroxbuster is not installed. Skipping scan.");

            return Err(ScanError::NotInstalled);
        }

        return Ok(Vec::new());
    }

    fn parse_output(&self) -> Vec<Self::ScanResult> {
        todo!()
    }

    fn print_results(&self, scan_results: &[Self::ScanResult]) {
        todo!()
    }

    fn triggers_on() {
        todo!()
    }
}