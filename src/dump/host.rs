use std::net::IpAddr;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Host {
	pub hostname: String,
	pub addr: IpAddr,
}
