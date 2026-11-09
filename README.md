# SigmaScope: Network telescope/IP darknet rule generator

Converts IPAM information sets into darknet-detecting SIEM queries, via Sigma.

## TODO

 - [ ] Allowlist
 - [ ] KQL for Defender Advanced Threat Hunting
 - [ ] Negative test cases/error handling
 - [ ] Docker
 - [ ] Templates

## Requirements

Python 3.14+ + `uv`, or docker

## Configuration

### Python

#### Output formats

Output formats are tied to [pySigma backends](https://github.com/SigmaHQ/pySigma#related-projects).

Enable backends using uv extras (choose from `splunk`, `kql`):
 - Splunk: `uv sync --extra splunk`
 - KQL: `uv sync --extra kql`
 - Multiple `uv sync --extra splunk --extra kql`
 - All of them: `uv sync --all-extras`

#### Pipelines

To fine-tune output fields beyond the pipelines included in the pySigma backend modules, add or use YAML pipelines in: [`src/pipelines/`](src/pipelines/).

[pySigma reference](https://sigmahq-pysigma.readthedocs.io/en/latest/guides/processing_pipelines.html)

## Inputs

IPAM data needs to be prepared into two files:

### [`Reserved addresses (CSV)`](src/tests/data/reserved.csv)

Simple list of IP addresses and ranges that are reserved for future use.

### [`Assigned addresses (CSV)`](src/tests/data/reserved.csv)

Simple list of IP addresses and ranges that are assigned to assets.

### Allowed addresses.

Additionally, you can provide a list of addresses or ranges that you are expecting - for instance security scanning tools.

## Usage

### Python

When exporting, chose a backend and pipeline.

Pipeline tweaks field names, backend (target) does the final conversion to the query.

```
cd src
uv run sigmascope.py [reservations CSV file] [assigned CSV file] [backend spec] [pipeline spec]
```

Examples:
```
uv run py sigmascope.py reserved.csv assigned.csv sigma.backends.splunk:SplunkBackend pipelines/splunk_cim_firewall_logs.yaml
uv run py sigmascope.py reserved.csv assigned.csv sigma.backends.splunk:SplunkBackend sigma.pipelines.splunk:splunk_windows_pipeline
```

## Tests

```
cd src
uv run py.test
```

## About

sigmascope heavily leverages and appreciates `pysigma` for output generation.
