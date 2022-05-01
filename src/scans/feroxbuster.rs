use std::{
    path::PathBuf,
    process::{Command, Stdio}, fs::{File, self}, io::BufReader,
};

use serde::{Deserialize, Serialize};
use url::Url;

use super::{error::ScanError, scan::Scan};
use crate::logger;
use which::which;

pub struct FeroxbusterScan {
    output_file: PathBuf,
    scan_args: Vec<String>,
}

// #[derive(Serialize, Deserialize, Debug)]
// struct FeroxResults {
//     pub items: Vec<FeroxbusterScanResult>
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct FeroxbusterScanResult {
    pub result_type: String,
    pub url: String,
    pub status: String,
    pub content_length: String,
}

impl FeroxbusterScan {
    pub fn new(mut output_dir: PathBuf, mut target: String) -> FeroxbusterScan {
        output_dir.push("feroxbuster");
        let mut wordlist_dir = std::env::current_exe().unwrap(); //Should be fine to unwrap() here since this function is also used in main.rs. Should've crashed back then already if this function fails.
        wordlist_dir.push("wordlists/feroxbuster-dir.txt");
        target.insert_str(0, "https://"); //Prepend the https:// protocol specifier.
        FeroxbusterScan {
            output_file: output_dir.clone(),
            scan_args: vec![
                String::from("-u"),
                String::from(target),
                String::from("-w"),
                String::from("/Users/mick/Workspace/Wordlists/common.txt"),
                // wordlist_dir.to_str().unwrap().to_string(),
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
                // let results = self.parse_output();
                // return Ok(results);
            }
            Err(err) => {
                // logger::print_err(&err.to_string());
                // return Err(ScanError::Runtime("feroxbuster".to_string()));
                return Err(ScanError::Runtime("eeek".to_string()));
            }
        }
    }

    fn parse_output(&self) -> Vec<Self::ScanResult> {
        println!("Reading from {}", self.output_file.to_str().unwrap());
        
        match fs::read_to_string(&self.output_file) {
            Ok(data) => {
                let test: Vec<FeroxbusterScanResult> = serde_json::from_str(&data.trim()).unwrap();
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
