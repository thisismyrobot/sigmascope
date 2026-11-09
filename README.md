# SigmaScope: Network telescope/IP darknet rule generator

Converts IPAM information sets into darknet-detecting SIEM queries, via Sigma.

## TODO

 - [ ] Allowlist
 - [x] KQL for Defender Advanced Threat Hunting
 - [ ] Negative test cases/error handling
 - [ ] Enforce `allowed_backends`
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

To fine-tune output fields beyond the pipelines included in the pySigma backend modules, add or use YAML pipelines in: [`src/pipelines/`](pipelines/).

[pySigma reference](https://sigmahq-pysigma.readthedocs.io/en/latest/guides/processing_pipelines.html)

https://github.com/SigmaHQ/pySigma-plugin-directory/blob/main/pySigma-plugins-v1.json

## Inputs

IPAM data needs to be prepared into two files:

### [`Reserved addresses (CSV)`](tests/data/reserved.csv)

Simple list of IP addresses and ranges that are reserved for future use.

### [`Assigned addresses (CSV)`](tests/data/reserved.csv)

Simple list of IP addresses and ranges that are assigned to assets.

### Allowed addresses.

Additionally, you can provide a list of addresses or ranges that you are expecting - for instance security scanning tools.

## Usage

### Python

When exporting, chose a backend and pipeline.

Pipeline tweaks field names, backend (target) does the final conversion to the query.

```
uv run sigmascope.py [reservations CSV file] [assigned CSV file] [backend spec] [pipeline spec]
```

Examples:
```
uv run sigmascope.py tests/data/reserved.csv tests/data/assigned.csv sigma.backends.splunk:SplunkBackend pipelines/splunk_cim_firewall_logs.yaml
uv run sigmascope.py tests/data/reserved.csv tests/data/assigned.csv sigma.backends.splunk:SplunkBackend sigma.pipelines.splunk:splunk_windows_pipeline
uv run sigmascope.py tests/data/reserved.csv tests/data/assigned.csv sigma.backends.kusto:KustoBackend pipelines/defender_xdr.yaml
```

## Tests

```
uv run py.test
```

## About

sigmascope heavily leverages and appreciates `pysigma` for output generation.
