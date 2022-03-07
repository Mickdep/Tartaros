use std::path::PathBuf;

use url::Url;

use super::scan::Scan;

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

    fn run(&self) -> Vec<Self::ScanResult> {
        todo!()
    }

    fn parse_output(&self) -> Vec<Self::ScanResult> {
        todo!()
    }

    fn print_results(&self, scan_results: &Vec<Self::ScanResult>) {
        todo!()
    }

    fn triggers_on() {
        todo!()
    }
}