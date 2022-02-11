pub trait ScanTrait {
    fn start(&self, target: &str) -> bool;
    fn parse_output(&self);
    fn print_results(&self);
    fn triggers_on(&self);
}
