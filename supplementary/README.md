# Supplementary source archive

`original/` preserves selected source files, parameter files, measurement JSON/CSV files and original reproduction notes associated with the paper's supplement. Paths below this directory mirror the original project-relative layout. `provenance.json` records the original path, exact SHA-256 and size of every copied file; the bytes were not rewritten.

The archive contains 792 files, including 259 source/build-script files. It covers the selected optimization campaigns, conventional controls, finite algebra/security-source screens and additional evidence referenced by the manuscript. Some data record failures, rejected parameter choices or adverse comparisons. Those outcomes are retained.

This is an inspectable historical archive. Original campaign entry points may depend on historical build directories, hard-coded development paths, additional tools or files outside the selected archive. They have not all been made portable or executed during this release. Follow the root README and the `native/`, `openfhe/`, `helib/` and `theory/` entry points for the supported reproduction workflows. Do not infer an executable reproduction claim from the presence of a source file.

[The coverage ledger](../docs/SUPPLEMENTARY_COVERAGE.md) maps the manuscript's provenance entries to included files and identifies external or unresolved items. This archive omits downloaded HE-library trees, compiled binaries, cryptographic key material, research checkpoints and duplicate manuscript snapshots. The matching manuscript is supplied separately in `paper/`.

Original notes and receipts can contain historical machine/path metadata and instructions that describe their earlier development environment. They serve as provenance rather than instructions for the portable release. Published data remain separate from the fresh validation records in the component directories.
