mod cli;
mod diagnostic;
mod executor;
mod fault;
mod filesystem;
mod hash;
mod identity;
mod ledger;
mod lock;
mod manifest;
mod reconcile;
#[cfg(test)]
mod scratch;
mod target;

use std::ffi::OsString;
use std::process::ExitCode;

pub fn run(args: Vec<OsString>) -> ExitCode {
    cli::run(&args)
}
