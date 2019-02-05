extern crate clap;
use clap::App;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const AUTHORS: &'static str = env!("CARGO_PKG_AUTHORS");

fn main() {
	let matches = App::new("nessify")
		.version(VERSION)
		.author(AUTHORS)
		.get_matches();
}
