# Third-party software

`wazuhcoverage` is distributed under GPL-2.0-only, but it depends on software
distributed under its own license. Those licenses apply to the respective
third-party components, not to `wazuhcoverage` itself.

The base installation has these direct runtime dependencies:

| Component | Use in `wazuhcoverage` | License | License reference |
| --- | --- | --- | --- |
| [DuckDB](https://duckdb.org/) | Reading and aggregating Wazuh JSON archives | MIT | [DuckDB license](https://github.com/duckdb/duckdb/blob/main/LICENSE) |
| [Drain3](https://github.com/IBM/Drain3) | Mining message templates used to group findings | MIT | [Drain3 license](https://github.com/IBM/Drain3/blob/master/LICENSE) |

Drain3 is the dependency used by this project; it is an implementation of the
Drain log-parsing algorithm. It should not be confused with a package named
`drain2`.

This list covers direct dependencies in the base installation. Python package
installers may also install transitive dependencies selected by the resolver.
The installed distributions contain their applicable license metadata and
license files; consult those files for the exact versions in a particular
environment.

