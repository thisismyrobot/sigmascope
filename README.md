# SigmaScope (WIP)

SigmaScope is Network telescope/IP darknet threat hunting query generator.

Converts IPAM information sets into darknet-detecting SIEM queries, via Sigma.

## Purpose

The goal is to simplify the process of searching firewall logs for traffic targeting IP darknet ranges, buy converting assigned, reserved, and know-good source ip addresses and range information into threat hunting queries.

## TODO

 - [x] Allow-list source networks
 - [x] KQL for Defender Advanced Threat Hunting
 - [ ] Negative test cases/error handling
 - [ ] Enforce `allowed_backends`
 - [ ] Drop `/32` postfixes
 - [ ] Docker
 - [ ] Templates
 - [ ] Sigma debug output

## Requirements

Python 3.14+ and [`uv`](https://docs.astral.sh/uv/getting-started/installation/)

## Data flow

### Output formats

Output formats are tied to [pySigma backends](https://github.com/SigmaHQ/pySigma#related-projects).

Enable backends using uv extras (choose from `splunk`, `kql`):
 - Splunk: `uv sync --extra splunk`
 - KQL: `uv sync --extra kql`
 - Multiple `uv sync --extra splunk --extra kql`
 - All of them: `uv sync --all-extras`

### Pipelines

To fine-tune output fields beyond the pipelines included in the pySigma backend modules, add or use YAML pipelines in: [`src/pipelines/`](pipelines/).

[pySigma reference](https://sigmahq-pysigma.readthedocs.io/en/latest/guides/processing_pipelines.html)

https://github.com/SigmaHQ/pySigma-plugin-directory/blob/main/pySigma-plugins-v1.json

### Input data

IPAM data needs to be prepared into two files:

#### Reserved addresses (CSV)

Simple list of IP addresses and ranges that are reserved for future use.

[Example](tests/data/reserved.csv)

#### Assigned addresses (CSV)

Simple list of IP addresses and ranges that are assigned to assets.

[Example](tests/data/assigned.csv)

### Allowed addresses.

Additionally, you can provide a list of addresses or ranges that you are expecting - for instance security scanning tools.

[Example](tests/data/allowed.csv)

## Usage

### Python

When exporting, chose a backend and pipeline.

Pipeline tweaks field names, backend (target) does the final conversion to the query.

```
usage: sigmascope.py [-h] [--allowed_source_nets ALLOWED_SOURCE_NETS]
                     reserved_csv assigned_csv target_spec pipeline_spec

positional arguments:
  reserved_csv          CSV file of reserved IP addresses and ranges (in CIDR notation)
  assigned_csv          CSV file of assigned IP addresses and ranges (in CIDR notation)
  target_spec           sigma.backends.[module]:[constructor]
  pipeline_spec         sigma.pipelines.[module]:[constructor] or pass a pipeline YAML file path

options:
  -h, --help            show this help message and exit
  --allowed_source_nets ALLOWED_SOURCE_NETS
                        CSV file of known-good allowed source addresses (e.g., internal scanners)
```

Examples:
```
uv run sigmascope.py tests/data/reserved.csv tests/data/assigned.csv sigma.backends.splunk:SplunkBackend pipelines/splunk_cim_firewall_logs.yaml
uv run sigmascope.py tests/data/reserved.csv tests/data/assigned.csv sigma.backends.splunk:SplunkBackend sigma.pipelines.splunk:splunk_windows_pipeline
uv run sigmascope.py tests/data/reserved.csv tests/data/assigned.csv sigma.backends.kusto:KustoBackend pipelines/defender_xdr.yaml --allowed_csv=tests/data/allowed.csv
```

## Tests

```
uv run py.test
```

## About

sigmascope heavily leverages and appreciates `pysigma` for output generation.

These links proved invaluable too:
 - https://www.dogesec.com/blog/beginners_guide_to_using_sigma_cli_pysigma/
 - https://threatclaw.io/en/blog/sigma-to-sentinel-kql
 - https://sigmahq.io/sigma-specification/specification/sigma-appendix-taxonomy.html
 - https://sigmahq-pysigma.readthedocs.io/en/latest/guides/processing_pipelines.html
 - https://help.splunk.com/en/splunk-cloud-platform/common-information-model/5.1/data-models/cim-fields-per-associated-data-model
