# Contributing

1. Open an issue describing the trust failure or missing evidence.
2. Keep changes narrow and use only the Python standard library unless a dependency removes more risk than it adds.
3. Add or update a test for every detection change.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run the tool against this repository with `--fail-on high`.
6. Do not commit real credentials, private records, compiled bytecode, archives, generated caches, or third-party personal data.

Detection changes must document likely false positives and must not claim to establish author intent.
