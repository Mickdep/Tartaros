use super::error::{self, ScanError};

//Not entirely happy about the fact that all the functions in this trait are also available from outside the implementing struct.\
//In an ideal case only the 'run()' function is public to the caller. Currently all functions are visible to the caller.
//This is something I'd like to fix in the future, if possible.
pub trait Scan {
    //This is awesome lol. This is called an "Associated type" and it functions as a polymorphic type.
    //Each struct that implements this trait must define this type. The scan "NmapScan" can for example define the following:
    //  type ScanResult = NmapScanResult;
    //While the scan "FeroxbusterScan" can define the following:
    //  type ScanResult = FeroxbusterScanResult;
    //This allows me to define a polymorphic return type.
    //https://doc.rust-lang.org/rust-by-example/generics/assoc_items/types.html
    //I might also implement this for return error types in the future.
    ///Associated type that is used to encapsulate results from scans
    type ScanResult;

    fn run(&self) -> Result<Vec<Self::ScanResult>, ScanError>;
    
    ///Parses scan output from a file (e.g. XML, JSON, etc.) to a Vec of `ScanResult`.
    fn parse_output(&self) -> Vec<Self::ScanResult>;

    fn print_results(&self, scan_results: &[Self::ScanResult]);
    fn print_command(&self);
    fn is_installed(&self) -> bool;
}
