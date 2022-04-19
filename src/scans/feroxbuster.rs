use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use url::Url;

use super::{error::ScanError, scan::Scan};
use crate::logger;
use which::which;

pub struct FeroxbusterScan {
    output_file: PathBuf,
    scan_args: Vec<String>,
}

pub struct FeroxbusterScanResult {
    pub url: Url,
    pub response_code: String,
    pub response_size: String,
}

impl FeroxbusterScan {
    pub fn new(mut output_dir: PathBuf, target: String) -> FeroxbusterScan {
        output_dir.push("feroxbuster");
        let mut wordlist_dir = std::env::current_dir().unwrap(); //Should be fine to unwrap() here since this function is also used in main.rs. Should've crashed back then already if this function fails.
        wordlist_dir.push("wordlists/feroxbuster-dir.txt");
        FeroxbusterScan {
            output_file: output_dir.clone(),
            scan_args: vec![
                String::from("-u"),
                String::from(target),
                String::from("-w"),
                wordlist_dir.to_str().unwrap().to_string(),
                String::from("-o"),
                output_dir.to_str().unwrap().to_string(),
                String::from("--json")
            ],
        }
    }
}

impl Scan for FeroxbusterScan {
    type ScanResult = FeroxbusterScanResult;

    fn run(&self) -> Result<Vec<Self::ScanResult>, ScanError> {
        if let Err(_) = which("feroxbuster") {
            logger::print_err("Feroxbuster is not installed. Skipping scan.");
            // let test = std::env::current_dir().unwrap();
            return Err(ScanError::NotInstalled("feroxbuster".to_string()));
        }

        logger::print_ok("Running Feroxbuster...");
        self.print_command();

        match Command::new("feroxbuster")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .args(&self.scan_args)
            .spawn()
        {
            Ok(mut child) => {
                if let Ok(_) = child.wait() {
                    //Feroxbuster ran successfully.
                    let results = self.parse_output();
                    self.print_results(&results);
                    return Ok(results);
                } else {
                    return Err(ScanError::Runtime("feroxbuster".to_string()));
                }
            }
            Err(err) => {
                logger::print_err(&err.to_string());
                return Err(ScanError::Runtime("feroxbuster".to_string()));
            }
        }
    }

    fn parse_output(&self) -> Vec<Self::ScanResult> {
        todo!()
    }

    fn print_results(&self, scan_results: &[Self::ScanResult]) {
        todo!()
    }

    fn print_command(&self) {
        logger::print_ok(&format!(
            "Command used: feroxbuster {}",
            self.scan_args.join(" ")
        ));
    }

    fn is_installed() -> bool {
        //Can probably be done more elegantly, but this is at least readable.
        if let Ok(_) = which("feroxbuster"){
            return true
        }
        false
    }
}
