#![forbid(unsafe_code)]

use log::*;
use structopt::StructOpt;
use std::fs::File;

use kuznechik::{encode, decode};

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

    if opts.encode ^ opts.decode != true {
        panic!("You must specify exactly one decode/encode argument");
    }

    let mut input = File::open(opts.input).expect("failed to open input file");
    let mut output = File::create(opts.output).expect("failed to open output file");

    let res = if opts.encode {
        encode(input, output)
    } else {
        decode(input, output)
    };

    if let Err(err) = res {
        error!("{:#}", err);
        std::process::exit(1);
    }
}
