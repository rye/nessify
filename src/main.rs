extern crate csv;

extern crate clap;
use clap::{App, Arg};

use nessify::*;
use std::fs::File;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

fn main() {
	let matches = App::new("nessify")
		.version(VERSION)
		.author(AUTHORS)
		.arg(
			Arg::with_name("config")
				.value_name("FILE")
				.short("c")
				.long("config")
				.help("Sets a configuration file to load before applying arguments")
				.takes_value(true),
		)
		.arg(
			Arg::with_name("dump")
				.value_name("DUMP")
				.multiple(true)
				.required(true),
		)
		.get_matches();

	let config = matches.value_of("config").unwrap_or("config.yml");
	println!("Configuration: {}", config);

	match matches.values_of("dump") {
		Some(results) => {
			for dump in results {
				println!("Dumps: {:?}", dump);

				let file = File::open(dump).unwrap();

				Dump::read(file);
			}
		}
		None => panic!("No dump filenames given; cannot do anything."),
	}
}
