// {Host, Protocol, Port} => Host
// {Plugin ID, CVE, CVSS, Name, Synopsis, Description, Solution, See Also} => Plugin
// {Plugin Output} => Detection (&Host, &Plugin) also

#[derive(Debug, Deserialize)]
struct Record {
	plugin_id: i32,
	cve: String,
	cvss: String,
	risk: String,
	host: String,
	protocol: String,
	port: u32,
	name: String,
	synopsis: String,
	description: String,
	solution: String,
	see_also: String,
	plugin_output: String,
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
