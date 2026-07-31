use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    furnish_coordinator::run(env::args_os().skip(1).collect())
}
