use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
};

use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{error::ScanError, scan::Scan};
use crate::logger;
use which::which;

pub struct FeroxbusterScan {
    output_file: PathBuf,
    scan_args: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct FeroxbusterScanResult {
    pub url: String,
    pub status: u32,
    pub word_count: u32,
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
                String::from("--json"),
            ]
        }
    }
}

impl Scan for FeroxbusterScan {
    type ScanResult = FeroxbusterScanResult;

    fn run(&self) -> Result<Vec<Self::ScanResult>, ScanError> {
        if !self.is_installed(){
            logger::print_err("Feroxbuster is not installed. Skipping scan.");
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
        let mut results: Vec<FeroxbusterScanResult> = Vec::new();
        if let Ok(file_handle) = File::open(&self.output_file) {
            let reader = BufReader::new(file_handle);
            for line in reader.lines() {
                if let Ok(line_read) = line {
                    let json_result = serde_json::from_str(&line_read);
                    if let Ok(feroxbuster_scan_result) = json_result {
                        results.push(feroxbuster_scan_result);
                    }
                }
            }
        } else {
            logger::print_err("Something went wrong when reading the feroxbuster output.");
        }

        return results;
    }

    fn print_results(&self, scan_results: &[Self::ScanResult]) {
        if scan_results.len() < 1 {
            logger::print_warn("Feroxbuster found nothing.");
            return;
        }
        let mut table = Table::new();

        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec!["Status", "URL", "Word count"]);

        for result in scan_results {
            table.add_row(vec![
                &result.status.to_string(),
                &result.url,
                &result.word_count.to_string(),
            ]);
        }

        println!("{}", table);
    }

    fn print_command(&self) {
        logger::print_ok(&format!(
            "Command used: feroxbuster {}",
            self.scan_args.join(" ")
        ));
    }

    fn is_installed(&self) -> bool {
        if let Ok(_) = which("feroxbuster"){
            return true;
        }
        false
    }
}
