use nessify::dump::*;

#[test]
fn parses_no_records_if_schema_is_bad() {
	let data = "invalid,csv
what are you,doing";

	let dump: Dump = Dump::read(data.as_bytes());

	dbg!(dump.clone());

	assert_eq!(dump.clone().filename, "test");
	assert_eq!(dump.clone().detections.len(), 0);
}
