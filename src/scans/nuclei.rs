use std::{path::PathBuf, process::{Stdio, Command}, fs};
use which::which;
use serde::{Serialize, Deserialize};
use crate::logger;

use super::{scan::Scan, error::ScanError};

#[derive(Serialize, Deserialize, Debug)]
pub struct NucleiScanResult {
    severity: String,
    #[serde(rename = "template-id")]
    template_id: String, //template-id
    #[serde(rename = "type")]
    template_type: String, //type
    #[serde(rename = "extracted-results")]
    finding_value: String, //extracted-results
    #[serde(rename = "matched-at")]
    location: String //matched-at
}

pub struct NucleiScan{
    output_file: PathBuf,
    scan_args: Vec<String>
}

impl NucleiScan {
    pub fn new(mut output_dir: PathBuf, target: String) -> NucleiScan {
        output_dir.push("nuclei");
        NucleiScan { 
            output_file: output_dir.clone(), 
            scan_args: vec![
                String::from("-u"),
                String::from(target),
                String::from("-ni"), //Don't use Interact.sh server to test for OOB interactions. Might miss some vulns.
                String::from("-o"),
                String::from(output_dir.to_str().unwrap())
            ]
        }
    }
}

impl Scan for NucleiScan {
    type ScanResult = NucleiScanResult;

    fn run(&self) -> Result<Vec<Self::ScanResult>, super::error::ScanError> {
        if !self.is_installed(){
            logger::print_err("Nuclei is not installed. Skipping scan.");
            return Err(ScanError::NotInstalled("feroxbuster".to_string()));
        }
        logger::print_ok("Running Nuclei ...");
        self.print_command();

        match Command::new("nuclei").stdout(Stdio::null())
        .stderr(Stdio::null())
        .args(&self.scan_args)
        .spawn() {
            Ok(mut child) => {
                if let Ok(_) = child.wait() {
                    //Feroxbuster ran successfully.
                    let results = self.parse_output();
                    self.print_results(&results);
                    return Ok(results);
                } else {
                    return Err(ScanError::Runtime("nuclei".to_string()));
                }
            }
            Err(err) => {
                return Err(ScanError::Runtime("eeek".to_string()));
            }
        }
    }

    fn parse_output(&self) -> Vec<Self::ScanResult> {
        match fs::read_to_string(&self.output_file) {
            Ok(data) => {
                let test: Vec<NucleiScanResult> = serde_json::from_str(&data.trim()).unwrap();
                for i in test {
                    println!("Ferox: {}", i.url);
                }
            }
            Err(error) => println!("Error reading file: {}", error),
        }
        // let reader = BufReader::new(file);
        // let test: Vec<FeroxbusterScanResult> = serde_json::from_reader(reader).unwrap();

        return Vec::new();
    }

    fn print_results(&self, scan_results: &[Self::ScanResult]) {
        todo!()
    }

    fn print_command(&self) {
        todo!()
    }

    fn is_installed(&self) -> bool {
        if let Ok(_) = which("nuclei"){
            return true;
        }
        false
    }
}

