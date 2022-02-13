use std::{
    fs::File,
    io::BufReader,
    iter::Scan,
    path::PathBuf,
    process::{Command, Stdio},
};

use super::scan::{self, ScanTrait};
use crate::logger;
use comfy_table::Table;
use xml::reader::XmlEvent;

pub struct NmapScan {
    output_dir: PathBuf,
    scan_results: Vec<ScanResult>,
    scan_args: Vec<String>,
}

struct ScanResult {
    port: u16,
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
        for elem in xml_reader {
            match elem {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    let mut scan_result = ScanResult {
                        port: Default::default(),
                        service_name: Default::default(),
                        service_version: Default::default(),
                    };

                    if name.local_name.eq("port") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("portid") {
                                scan_result.port = attr.value.parse::<u16>().unwrap();
                            }
                        }
                    }

                    if name.local_name.eq("service") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("product") {
                                scan_result.service_name = attr.value.clone();
                            }

                            if attr.name.local_name.eq("version") {
                                scan_result.service_version = attr.value.clone();
                            }
                        }
                    }

                    self.scan_results.push(scan_result);
                }
                Err(_) => {
                    logger::print_err("Error reading Nmap XML entry");
                }

                _ => {}
            }
        }
    }

    fn print_results(&self) {
        
        let mut table = Table::new();

        // table.set_header(vec!["Port", "Service", "Version"])
        //     .add_row(row);
    }

    fn triggers_on(&self) {
        todo!()
    }
}
