
pub trait ScanTrait {
    fn run(&mut self, target: &str);
    fn parse_output(&mut self);
    fn print_results(&self);
    fn triggers_on(&self);
}
