//! Writing to stdout without panicking when the reader goes away.
//!
//! `println!` panics if stdout is closed, so `briefcred audit | head` used to
//! end in a panic message instead of quietly. [`outln!`](crate::outln) and
//! [`out!`](crate::out) treat a closed stdout as the end of the command, the
//! way `head`, `grep -q` and every other pipeline reader expect. Any other
//! write error still fails loudly, as `println!` did.

use std::fmt;
use std::io::{ErrorKind, Write as _};

/// Write `args`, then a newline when `newline` is set.
pub fn write(args: fmt::Arguments<'_>, newline: bool) {
    let mut out = std::io::stdout().lock();
    let written = out.write_fmt(args).and_then(|()| {
        if newline {
            out.write_all(b"\n")
        } else {
            Ok(())
        }
    });
    match written {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::BrokenPipe => std::process::exit(0),
        Err(err) => panic!("failed printing to stdout: {err}"),
    }
}

/// `println!` that ends the command quietly when stdout has been closed.
#[macro_export]
macro_rules! outln {
    () => { $crate::output::write(format_args!(""), true) };
    ($($arg:tt)*) => { $crate::output::write(format_args!($($arg)*), true) };
}

/// `print!` that ends the command quietly when stdout has been closed.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => { $crate::output::write(format_args!($($arg)*), false) };
}
