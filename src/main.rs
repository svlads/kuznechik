#![forbid(unsafe_code)]

use log::*;
use std::fs::File;
use structopt::StructOpt;

use kuznechik::encode;

#[derive(StructOpt, Debug)]
#[structopt()]
struct Opts {
    /// Encode/Decode data
    #[structopt(short = "e", long = "encode")]
    encode: bool,
    #[structopt(short = "d", long = "decode")]
    decode: bool,

    /// Path to input file with text
    #[structopt(short = "i", long = "input")]
    input: String,
    /// Path to output file with text
    #[structopt(short = "o", long = "output")]
    output: String,
}

fn main() {
    let opts = Opts::from_args();

    stderrlog::new()
        .verbosity(5)
        .timestamp(stderrlog::Timestamp::Off)
        .init()
        .expect("failed to initialize logging");

    if !(opts.encode ^ opts.decode) {
        panic!("You must specify exactly one decode/encode argument");
    }

    let res = encode();

    if let Err(err) = res {
        error!("{:#}", err);
        std::process::exit(1);
    }
}
