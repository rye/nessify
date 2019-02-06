// {Host, Protocol, Port} => Host
// {Plugin ID, CVE, CVSS, Name, Synopsis, Description, Solution, See Also} => Plugin
// {Plugin Output} => Detection (&Host, &Plugin) also

#[derive(Debug, Deserialize)]
struct Record {
	#[serde(rename = "Plugin ID")]
	plugin_id: i32,
	#[serde(rename = "CVE")]
	cve: String,
	#[serde(rename = "CVSS")]
	cvss: String,
	#[serde(rename = "Risk")]
	risk: String,
	#[serde(rename = "Host")]
	host: String,
	#[serde(rename = "Protocol")]
	protocol: String,
	#[serde(rename = "Port")]
	port: u32,
	#[serde(rename = "Name")]
	name: String,
	#[serde(rename = "Synopsis")]
	synopsis: String,
	#[serde(rename = "Description")]
	description: String,
	#[serde(rename = "Solution")]
	solution: String,
	#[serde(rename = "See Also")]
	see_also: String,
	#[serde(rename = "Plugin Output")]
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
