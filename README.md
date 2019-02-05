# nessify

A Nessus scan dump parser and differ.

## Motivation

In particularly large organizations, there can be tens of thousands of
findings in a Nessus scan.  While large amounts of work could be
performed for each scan, sometimes what is more interesting is to
understand the difference between two scans entirely.

This project aims to make it easier for people to process and
understand Nessus scan results.  It includes a parsing library which
loads uncompressed _or compressed_ CSV files in the Nessus export
format, and then optionally compares the results from two dumps to
find any differences.

## License

This project is currently licensed under my default license, the MIT
license.  For more information, see the `LICENSE` file at the root of
this document.
