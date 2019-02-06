use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

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

#[derive(Clone, Eq)]
struct Plugin {
	id: i32,
	cve: Vec<String>,
	cvss: String,
	risk: String,
	name: String,
	synopsis: String,
	description: String,
	solution: String,
	see_also: String,
}

impl PartialEq for Plugin {
	fn eq(&self, other: &Plugin) -> bool {
		let mut s = DefaultHasher::new();
		let mut o = DefaultHasher::new();
		self.hash(&mut s);
		other.hash(&mut o);
		s.finish() == o.finish()
	}
}

impl Hash for Plugin {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.id.hash(state);
		self.cvss.hash(state);
		self.risk.hash(state);
		self.name.hash(state);
		self.synopsis.hash(state);
		self.description.hash(state);
		self.solution.hash(state);
		self.see_also.hash(state);
	}
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct Host {
	hostname: String,
	addr: IpAddr,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct Detection {
	host: Host,
	port: u32,
	protocol: String,
	plugin: Plugin,
	plugin_output: String,
}

pub struct Dump {
	filename: String,
}

impl Dump {
	pub fn read<R: std::io::Read>(rdr: R) -> Dump {
		let mut reader = csv::Reader::from_reader(rdr);

		let mut plugins: HashSet<Plugin> = HashSet::new();
		let mut hosts: HashSet<Host> = HashSet::new();
		let mut detections: HashSet<Detection> = HashSet::new();

		reader
			.deserialize()
			.filter_map(|result| -> Option<Record> { result.ok() })
			.for_each(|record| {
				let record_plugin = Plugin {
					id: record.plugin_id,
					cve: vec![record.cve],
					cvss: record.cvss,
					risk: record.risk,
					name: record.name,
					synopsis: record.synopsis,
					description: record.description,
					solution: record.solution,
					see_also: record.see_also,
				};

			});

		println!("plugins: {}", plugins.len());
		println!("hosts: {}", hosts.len());
		println!("detections: {}", detections.len());

		Dump {
			filename: "test".to_string(),
		}
	}
}
