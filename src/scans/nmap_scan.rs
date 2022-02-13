use std::{
    fs::File,
    io::BufReader,
    iter::Scan,
    path::PathBuf,
    process::{Command, Stdio},
};

use super::scan::{self, ScanTrait};
use crate::logger::{self, print_warn};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use xml::reader::XmlEvent;

pub struct NmapScan {
    output_dir: PathBuf,
    scan_results: Vec<ScanResult>,
    scan_args: Vec<String>,
}

struct ScanResult {
    port: String,
    service_name: String,
    service_version: String,
}

impl NmapScan {
    pub fn new(mut output_dir: PathBuf) -> NmapScan {
        output_dir.push("nmap");
        NmapScan {
            output_dir,
            scan_results: Vec::new(),
            scan_args: vec![
                String::from("-sV"),
                String::from("-sC"),
                String::from("-oX"),
            ],
        }
    }
}

impl ScanTrait for NmapScan {
    fn start(&mut self, target: &str) -> bool {
        logger::print_ok("Running Nmap...");
        let mut args = vec![
            self.output_dir.to_str().unwrap().to_string(),
            target.to_string(),
        ];
        self.scan_args.append(&mut args);

        logger::print_ok(&format!("Command used: nmap {}", self.scan_args.join(" ")));

        match Command::new("nmap")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .args(&self.scan_args)
            .spawn()
        {
            Ok(mut child) => {
                if let Ok(status) = child.wait() {
                    if status.success() {
                        return true;
                    }
                }
            }
            Err(err) => {
                logger::print_err(&err.to_string());
            }
        }

        false
    }

    fn parse_output(&mut self) {
        // let xmldoc = xml::reader::EventReader::new(self.output_dir.to_str().unwrap());'
        let file = File::open(&self.output_dir).unwrap();
        let buf_reader = BufReader::new(file);
        let xml_reader = xml::EventReader::new(buf_reader);
        let mut scan_result = ScanResult {
            port: String::from(""),
            service_name: String::from(""),
            service_version: String::from(""),
        };
        let mut done = false;
        for elem in xml_reader {
            match elem {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    if name.local_name.eq("port") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("portid") {
                                scan_result.port.push_str(&attr.value);
                            }
                        }
                    }

                    if name.local_name.eq("service") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("name") {
                                scan_result.service_name.push_str(&attr.value);
                            }

                            if attr.name.local_name.eq("product") {
                                if scan_result.service_name != "" {
                                    scan_result.service_name.push_str(": ");
                                }
                                scan_result.service_name.push_str(&attr.value.clone());
                            }

                            if attr.name.local_name.eq("version") {
                                scan_result.service_version.push_str(&attr.value.clone());
                                done = true;
                            }
                        }
                    }

                    if done {
                        self.scan_results.push(scan_result);
                        scan_result = ScanResult {
                            port: String::from(""),
                            service_name: String::from(""),
                            service_version: String::from(""),
                        };

                        done = false;
                    }
                }
                Err(_) => {
                    logger::print_err("Error reading Nmap XML entry");
                }

                _ => {}
            }
        }
    }

    fn print_results(&self) {
        if self.scan_results.len() < 1 {
            logger::print_warn("No open ports found.");
            return;
        }
        let mut table = Table::new();

        table
            .set_header(vec!["Port", "Service", "Version"])
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);

        for result in &self.scan_results {
            println!(
                "{}/{}/{}",
                &result.port, &result.service_name, &result.service_version,
            );
            table.add_row(vec![
                &result.port,
                &result.service_name,
                &result.service_version,
            ]);
        }

        println!("{}", table);
    }

    fn triggers_on(&self) {
        todo!()
    }
}
