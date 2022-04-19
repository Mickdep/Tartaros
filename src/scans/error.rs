#[derive(Debug)]
pub enum ScanError {
    NotInstalled(String),
    Runtime(String),
    None
}