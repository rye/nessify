use std::collections::HashSet;

mod host;
mod plugin;
mod record;

#[derive(Clone, Hash, Eq, PartialEq)]
struct Detection {
	host: Host,
	port: u32,
	protocol: String,
	plugin: Plugin,
	plugin_output: String,
}
use host::*;
use plugin::*;
use record::*;

#[allow(dead_code)]
pub struct Dump {
	filename: String,
	detections: Vec<Detection>,
}

impl Dump {
	pub fn read<R: std::io::Read>(rdr: R) -> Dump {
		let mut reader = csv::Reader::from_reader(rdr);

		let mut plugins: HashSet<Plugin> = HashSet::new();
		let mut hosts: HashSet<Host> = HashSet::new();
		let mut detections: HashSet<Detection> = HashSet::new();

		// TODO refactor for efficiency and conciseness
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

				let record_host = Host {
					hostname: record.host.clone(),
					addr: record.host.parse().unwrap(),
				};

				if let Some(plugin) = plugins.get(&record_plugin) {
					if !plugin.cve.contains(record_plugin.cve.first().unwrap()) {
						plugins.replace(Plugin {
							cve: [plugin.cve.as_slice(), record_plugin.cve.as_slice()].concat(),
							..(plugin.clone())
						});

						print!("p");
					}
				} else {
					assert_eq!(plugins.insert(record_plugin.clone()), true);

					print!("P");
				}

				let host = hosts.get(&record_host);

				if host.is_none() {
					assert_eq!(hosts.insert(record_host.clone()), true);
					print!("H")
				}

				let plugin: Plugin = plugins.get(&record_plugin).unwrap().clone();
				let host: Host = hosts.get(&record_host).unwrap().clone();

				let record_detection = Detection {
					host,
					plugin,
					plugin_output: record.plugin_output,
					port: record.port,
					protocol: record.protocol,
				};

				detections.insert(record_detection);
			});

		println!();

		println!("plugins: {}", plugins.len());
		println!("hosts: {}", hosts.len());
		println!("detections: {}", detections.len());

		Dump {
			filename: "test".to_string(),
			detections: detections.iter().cloned().collect(),
		}
	}
}
