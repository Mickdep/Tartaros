use crate::logger;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, *};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
};
use which::which;

use super::{error::ScanError, scan::Scan};

#[derive(Serialize, Deserialize, Debug)]
pub struct NucleiScanResult {
    info: Info,
    #[serde(rename = "template-id")]
    template_id: String, //template-id
    #[serde(rename = "type")]
    template_type: String, //type
    #[serde(rename = "extracted-results", default)]
    finding_values: Vec<String>, //extracted-results
    #[serde(rename = "matcher-name", default)]
    matcher_name: String,
    #[serde(rename = "matched-at")]
    location: String, //matched-at
}

#[derive(Serialize, Deserialize, Debug)]
struct Info {
    severity: String,
}

pub struct NucleiScan {
    output_file: PathBuf,
    scan_args: Vec<String>,
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
                String::from("-fr"), //Follow redirects
                String::from("-o"),
                String::from(output_dir.to_str().unwrap()),
                String::from("-json"),
            ],
        }
    }
}

impl Scan for NucleiScan {
    type ScanResult = NucleiScanResult;

    fn run(&self) -> Result<Vec<Self::ScanResult>, super::error::ScanError> {
        if !self.is_installed() {
            logger::print_err("Nuclei is not installed. Skipping scan.");
            return Err(ScanError::NotInstalled("feroxbuster".to_string()));
        }
        logger::print_ok("Running Nuclei ...");
        self.print_command();

        // match Command::new("nuclei")
        //     .stdout(Stdio::null())
        //     .stderr(Stdio::null())
        //     .args(&self.scan_args)
        //     .spawn()
        // {
        //     Ok(mut child) => {
        //         if let Ok(_) = child.wait() {
        let results = self.parse_output();
        self.print_results(&results);
        return Ok(results);
        // } else {
        //     return Err(ScanError::Runtime("nuclei".to_string()));
        // }
        // }
        // Err(err) => {
        //     logger::print_err(&err.to_string());
        //     return Err(ScanError::Runtime("nuclei".to_string()));
        // }
        // }
    }

    fn parse_output(&self) -> Vec<Self::ScanResult> {
        let mut results: Vec<NucleiScanResult> = Vec::new();
        if let Ok(file_handle) = File::open(&self.output_file) {
            let reader = BufReader::new(file_handle);
            for line in reader.lines() {
                if let Ok(line_read) = line {
                    let json_result = serde_json::from_str(&line_read);
                    match json_result {
                        Ok(nuclei_scan_result) => {
                            results.push(nuclei_scan_result);
                        }
                        Err(err) => {
                            println!("Fuck! Can't unpack the nuclei results. {}", err.to_string())
                        }
                    }
                }
            }
        } else {
            logger::print_err("Something went wrong when reading the nuclei output.");
        }

        return results;
    }

    fn print_results(&self, scan_results: &[Self::ScanResult]) {
        if scan_results.len() < 1 {
            logger::print_warn("Nuclei found nothing."); //Will never happen lol
            return;
        }

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec![
                "Severity",
                "Template Id",
                "Template type",
                "Location",
                "Value",
            ]);

        for result in scan_results {
            //To make this loop have mutable references I need to implement the Itertor trait for the NucleiScanResult struct. Don't feel like doing that :P.
            //Extract all the values in 'extracted_results'
            let finding_value_string = result.finding_values.join(",");

            //Below we construct the template_id string. We want the template name as well as the matcher.
            let mut template_id_string = result.template_id.clone(); //Clone because of the reason stated in the comment for the loop.
            if result.matcher_name != String::default() {
                template_id_string.push(':');
                template_id_string.push_str(&result.matcher_name);
            }

            //Can be done more elegantly with a Hashmap but I dont care atm.
            let cell: Cell = Cell::new(&result.info.severity);
            let mut severity_color = Color::AnsiValue(33); //Make this default for an 'info' finding.
            if result.info.severity == "low" {
                severity_color = Color::AnsiValue(28);
            } else if result.info.severity == "medium" {
               severity_color = Color::AnsiValue(214);
            } else if result.info.severity == "high" {
                severity_color = Color::AnsiValue(196);
            } else if result.info.severity == "critical" {
                severity_color = Color::AnsiValue(196);
            }
            //c
            table.add_row(vec![
                cell.fg(severity_color),
                Cell::from(&template_id_string),
                Cell::from(&result.template_type),
                Cell::from(&result.location),
                Cell::from(&finding_value_string),
            ]);
        }

        println!("{}", table);
    }

    fn print_command(&self) {
        logger::print_ok(&format!(
            "Command used: nuclei {}",
            self.scan_args.join(" ")
        ));
    }

    fn is_installed(&self) -> bool {
        if let Ok(_) = which("nuclei") {
            return true;
        }
        false
    }
}