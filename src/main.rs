extern crate clap;
use clap::{App, Arg};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const AUTHORS: &'static str = env!("CARGO_PKG_AUTHORS");

fn main() {
	let matches = App::new("nessify")
		.version(VERSION)
		.author(AUTHORS)
		.arg(Arg::with_name("dump")
		     .multiple(true)
		     .required(true))
		.get_matches();

	match matches.values_of("dump") {
		Some(results) => {
			for dump in results {
				println!("Dumps: {:?}", dump);
			}
		},
		None => panic!("No dump filenames given; cannot do anything.")
	}
}
