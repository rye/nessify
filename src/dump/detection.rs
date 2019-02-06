use super::host::*;
use super::plugin::*;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Detection {
	pub host: Host,
	pub port: u32,
	pub protocol: String,
	pub plugin: Plugin,
	pub plugin_output: String,
}
