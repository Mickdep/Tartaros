pub trait Scan {
    //This is awesome lol. This is called an "Associated type" and it functions as a polymorphic type.
    //Each struct that implements this trait must define this type. The scan "NmapScan" can for example define the following:
    //type ScanResult = NmapScanResult;
    //While the scan "FeroxbusterScan" can define the following:
    //type ScanResult = FeroxbusterScanResult;
    //This allows me to define a polymorphic return type.
    //https://doc.rust-lang.org/rust-by-example/generics/assoc_items/types.html
    //I might also implement this for return error types in the future.
    type ScanResult;

    fn run(&self) -> Vec<Self::ScanResult>;
    fn parse_output(&self) -> Vec<Self::ScanResult>;
    fn print_results(&self, scan_results: &Vec<Self::ScanResult>);
    fn triggers_on();
}
