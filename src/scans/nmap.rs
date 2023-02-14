use std::{
    fmt,
    fs::File,
    io::BufReader,
    path::PathBuf,
    process::{Command, Stdio},
};

use super::{scan::Scan, error::ScanError};
use crate::logger;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use xml::reader::XmlEvent;

pub struct NmapScan {
    output_file: PathBuf,
    scan_args: Vec<String>,
}

pub enum PortState {
    Open,
    Filtered,
    None,
}

//This might be overkill.
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

pub struct Port {
    pub num: String,
    pub state: PortState,
}

//Has to be public because a Vec of this struct is returned.
pub struct NmapScanResult {
    pub port: Port,
    service_name: String,
    service_version: String,
}

impl NmapScan {
    pub fn new(mut output_dir: PathBuf, target: String) -> NmapScan {
        //Create a separate file for the raw output
        let mut output_file_raw = output_dir.clone();
        output_file_raw.push("nmap_raw");

        //Create a separate file for the XML output
        output_dir.push("nmap_xml");
        NmapScan {
            output_file: output_dir.clone(), //Clone here because the .to_str()'s below need it as well.
            scan_args: vec![
                String::from("-sV"),
                String::from("-sC"),
                String::from("-oX"),
                output_dir.to_str().unwrap().to_string(),
                String::from("-oN"),
                output_file_raw.to_str().unwrap().to_string(),
                target,
            ],
        }
    }
}

impl Scan for NmapScan {
    type ScanResult = NmapScanResult;

    fn run(&self) -> Result<Vec<NmapScanResult>, ScanError> {
        logger::print_ok("Running Nmap...");
        self.print_command();

        match Command::new("nmap")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .args(&self.scan_args)
            .spawn()
        {
            Ok(mut child) => {
                if let Ok(_) = child.wait() {
                    //Nmap ran successfully.
                    let results = self.parse_output();
                    self.print_results(&results);
                    return Ok(results);
                } else {
                    return Err(ScanError::Runtime("nmap".to_string()));
                }
            }
            Err(err) => {
                logger::print_err(&err.to_string());
                return Err(ScanError::Runtime("nmap".to_string()));
            }
        }
    }

    fn parse_output(&self) -> Vec<NmapScanResult> {
        println!("Now parsing nmap output");
        //Open the XML file and create a buffered reader for the XML reader.
        let file = File::open(&self.output_file).unwrap();
        let buf_reader = BufReader::new(file);
        let xml_reader = xml::EventReader::new(buf_reader);

        //Create an object that will constantly be updated
        let mut scan_results: Vec<NmapScanResult> = Vec::new();
        let mut scan_result = NmapScanResult {
            port: Port {
                num: String::from(""),
                state: PortState::None,
            },
            service_name: String::from(""),
            service_version: String::from(""),
        };
        //TODO: This parsing logic can possibly be a lot simpler. Another crate could be used for this instead of the default XML reader.
        //This parsing logic simply loops through ALL elements in the XML tree, and constructs NmapScanResults for entries on the fly.
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
                        scan_results.push(scan_result);
                        //Reinstantiate the ScanResult object so it can form a new instance.
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

        return scan_results;
    }

    fn print_results(&self, scan_results: &[NmapScanResult]) {
        if scan_results.len() < 1 {
            logger::print_warn("No open ports found.");
            return;
        }
        let mut table = Table::new();

        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec!["Port", "State", "Service", "Version"]);

        for result in scan_results {
            table.add_row(vec![
                &result.port.num,
                &result.port.state.to_string(),
                &result.service_name,
                &result.service_version,
            ]);
        }

        println!("{}", table);
    }

    fn print_command(&self) {
        logger::print_ok(&format!("Command used: nmap {}", self.scan_args.join(" ")));
    }

    /// NOT USED.
    /// This function is just here because it's mandatory to implement according to the trait.
    /// However, Nmap's installation is already checked in main.rs. If this function is reached, we know Nmap is installed already.
    /// Thus: always return true here.
    fn is_installed(&self) -> bool {
        true
    }
}
