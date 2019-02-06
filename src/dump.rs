// {Host, Protocol, Port} => Host
// {Plugin ID, CVE, CVSS, Name, Synopsis, Description, Solution, See Also} => Plugin
// {Plugin Output} => Detection (&Host, &Plugin) also

struct Record {
}

struct Plugin {
}

struct Host {
}

struct Detection {
}

pub struct Dump {
}

impl Dump {
	pub fn read<R: std::io::Read>(rdr: R) -> Dump {
		let mut reader = csv::Reader::from_reader(rdr);

		Dump {
			filename: "test".to_string(),
		}
	}
}
