use std::fmt;
use std::{
    fs::File,
    io::BufReader,
    path::PathBuf,
    process::{Command, Stdio},
};

use super::scan::ScanTrait;
use crate::logger::{self};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use xml::reader::XmlEvent;

pub struct NmapScan {
    output_file: PathBuf,
    pub scan_results: Vec<NmapScanResult>,
    scan_args: Vec<String>,
}


enum PortState {
    Open,
    Filtered,
    None,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => {
                write!(f, "Open")
            }
            PortState::Filtered => {
                write!(f, "Filtered")
            }
            PortState::None => {
                write!(f, "None")
            }
        }
    }
}

struct Port {
    num: String,
    state: PortState,
}

pub struct NmapScanResult {
    port: Port,
    service_name: String,
    service_version: String,
}

impl NmapScan {
    pub fn new(mut output_dir: PathBuf) -> NmapScan {
        //Create a separate file for the raw output
        let mut output_file_raw = output_dir.clone();
        output_file_raw.push("nmap_raw");

        //Create a separate file for the XML output
        output_dir.push("nmap_xml");
        NmapScan {
            output_file: output_dir.clone(), //Clone here because the .to_str()'s below need it as well.
            scan_results: Vec::new(),
            scan_args: vec![
                String::from("-sV"),
                String::from("-sC"),
                String::from("-oX"),
                output_dir.to_str().unwrap().to_string(),
                String::from("-oN"),
                output_file_raw.to_str().unwrap().to_string(),
            ],
        }
    }
}

impl ScanTrait for NmapScan {

    fn run(&mut self, target: &str) {
        logger::print_ok("Running Nmap...");
        self.scan_args.push(target.to_string());
        logger::print_ok(&format!("Command used: nmap {}", self.scan_args.join(" ")));
        logger::print_warn("Please note that the raw output of this scan will be shown at the end for further inspection.");

        match Command::new("nmap")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .args(&self.scan_args)
            .spawn()
        {
            Ok(mut child) => {
                if let Ok(_) = child.wait() {
                }else{
                    logger::print_err("Error running Nmap");
                }
            }
            Err(err) => {
                logger::print_err(&err.to_string());
            }
        }
    }

    fn parse_output(&mut self) {
        //Open the XML file and create a buffered reader for the XML reader.
        let file = File::open(&self.output_file).unwrap();
        let buf_reader = BufReader::new(file);
        let xml_reader = xml::EventReader::new(buf_reader);

        //Create an object that will constantly be updated
        let mut scan_result = NmapScanResult {
            port: Port {
                num: String::from(""),
                state: PortState::None,
            },
            service_name: String::from(""),
            service_version: String::from(""),
        };
        for elem in xml_reader {
            match elem {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    if name.local_name.eq("port") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("portid") {
                                scan_result.port.num.push_str(&attr.value);
                            }
                        }
                    }

                    if name.local_name.eq("state") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("state") {
                                if attr.value == "open" {
                                    scan_result.port.state = PortState::Open;
                                } else {
                                    //Just default to filtered because Nmap doesn't show closed ports...
                                    scan_result.port.state = PortState::Filtered;
                                }
                            }
                        }
                    }

                    if name.local_name.eq("service") {
                        for attr in attributes {
                            if attr.name.local_name.eq("name") {
                                scan_result.service_name.push_str(&attr.value);
                            }

                            if attr.name.local_name.eq("product") {
                                if scan_result.service_name != "" {
                                    scan_result.service_name.push_str(": ");
                                }
                                scan_result.service_name.push_str(&attr.value);
                            }

                            if attr.name.local_name.eq("version") {
                                scan_result.service_version.push_str(&attr.value);
                            }
                        }
                    }
                }

                Ok(XmlEvent::EndElement { name }) => {
                    if name.local_name.eq("port") {
                        //Reinstantiate the ScanResult object so it can form a new instance.
                        self.scan_results.push(scan_result);
                        scan_result = NmapScanResult {
                            port: Port {
                                num: String::from(""),
                                state: PortState::None,
                            },
                            service_name: String::from(""),
                            service_version: String::from(""),
                        }
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
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec!["Port", "State", "Service", "Version"]);

        for result in &self.scan_results {
            table.add_row(vec![
                &result.port.num,
                &result.port.state.to_string(),
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
