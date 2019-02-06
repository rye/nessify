// {Host, Protocol, Port} => Host
// {Plugin ID, CVE, CVSS, Name, Synopsis, Description, Solution, See Also} => Plugin
// {Plugin Output} => Detection (&Host, &Plugin) also

#[derive(Debug, Deserialize)]
pub struct Record {
	#[serde(rename = "Plugin ID")]
	pub plugin_id: i32,
	#[serde(rename = "CVE")]
	pub cve: String,
	#[serde(rename = "CVSS")]
	pub cvss: String,
	#[serde(rename = "Risk")]
	pub risk: String,
	#[serde(rename = "Host")]
	pub host: String,
	#[serde(rename = "Protocol")]
	pub protocol: String,
	#[serde(rename = "Port")]
	pub port: u32,
	#[serde(rename = "Name")]
	pub name: String,
	#[serde(rename = "Synopsis")]
	pub synopsis: String,
	#[serde(rename = "Description")]
	pub description: String,
	#[serde(rename = "Solution")]
	pub solution: String,
	#[serde(rename = "See Also")]
	pub see_also: String,
	#[serde(rename = "Plugin Output")]
	pub plugin_output: String,
}
