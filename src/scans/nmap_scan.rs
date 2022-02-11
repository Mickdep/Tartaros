use std::{process::{Command, Stdio}, path::PathBuf, io::BufReader, fs::File};

use xml::reader::XmlEvent;

use crate::logger;

use super::scan::ScanTrait;

pub struct NmapScan {
    output_dir: PathBuf,
}

impl NmapScan {
    pub fn new(mut output_dir: PathBuf) -> NmapScan {
        output_dir.push("nmap");
        NmapScan { output_dir }
    }
}

impl ScanTrait for NmapScan {
    fn start(&self, target: &str) -> bool {
        logger::print_ok("Running Nmap scan...");
        if let Ok(mut child) = Command::new("nmap")
            .stdout(Stdio::null())
            .args(["-sV", "-sC", "-oX", self.output_dir.to_str().unwrap(), target])
            .spawn()
        {
            if let Ok(status) = child.wait() {
                if status.success() {
                    return true;
                }
            }
        }

        false
    }

    fn parse_output(&self) {
        // let xmldoc = xml::reader::EventReader::new(self.output_dir.to_str().unwrap());'
        let file = File::open(&self.output_dir).unwrap();
        let buf_reader = BufReader::new(file);
        let xml_reader = xml::EventReader::new(buf_reader);
        for elem in xml_reader {
            match elem {
                Ok(XmlEvent::StartElement {name, attributes, ..}) => {
                    if name.local_name.eq("port") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("portid"){
                                logger::print_warn(&format!("Port {} is open", attr.value));
                            }
                        }
                    }

                    if name.local_name.eq("service") {
                        let mut output = String::from("");
                        for attr in &attributes {
                            if attr.name.local_name.eq("product"){
                                output.push_str("Product ");
                                output.push_str(&attr.value);
                            }

                            if attr.name.local_name.eq("version") {
                                output.push_str(" with version ");
                                output.push_str(&attr.value);
                            }
                        }
                        logger::print_warn(&format!("Service: {}", output));
                    }
                }

                Ok(XmlEvent::EndElement { name }) => {
                    continue;
                }
                Err(_) => {
                    logger::print_err("Error reading Nmap XML");
                }

                _ => {}
            }
        }
    }

    fn print_results(&self) {
        todo!()
    }

    fn triggers_on(&self) {
        todo!()
    }
}
