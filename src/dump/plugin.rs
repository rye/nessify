use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Eq)]
pub struct Plugin {
	pub id: i32,
	pub cve: Vec<String>,
	pub cvss: String,
	pub risk: String,
	pub name: String,
	pub synopsis: String,
	pub description: String,
	pub solution: String,
	pub see_also: String,
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
