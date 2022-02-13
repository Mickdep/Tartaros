pub trait ScanTrait {
    fn start(&mut self, target: &str) -> bool;
    fn parse_output(&mut self);
    fn print_results(&self);
    fn triggers_on(&self);
}
