use colored::Colorize;

pub fn print_ok(msg: &str) {
    println!("{} {}", "[+]".green(), msg.green());
}

pub fn print_err(msg: &str) {
    eprintln!("{} {}", "[!]".red(), msg.red())
}

pub fn print_warn(msg: &str) {
    println!("{} {}", "[~]".yellow(), msg.yellow());
}
