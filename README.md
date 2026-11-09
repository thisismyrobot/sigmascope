# SigmaScope: Network telescope/IP darknet rule generator

Converts IPAM information sets into SIEM queries, via Sigma.

## Requirements

Python 3.14+ + `uv`, or docker

## Output formats

Install plugins for backends and pipelines for the output formats you need

```
uv run sigma plugin install splunk
uv run sigma plugin install kusto
```

Or defined them in the `pipelines`

### Python

Add output format packages (choose from `splunk`, ... TODO):

`uv sync --extra splunk`
`uv sync --extra kql`

## Run

### Python

When exporting, chose a backend and pipeline.

Pipeline tweaks field names, backend (target) does the final conversion to the query.

```
cd src
uv run sigmascope.py [reservations CSV file] [assigned CSV file] [backend spec] [pipeline spec]
```

Examples:
```
sigmascope.py reserved.csv assigned.csv sigma.backends.splunk:SplunkBackend pipelines/splunk_cim_firewall_logs.yaml
sigmascope.py reserved.csv assigned.csv sigma.backends.splunk:SplunkBackend sigma.pipelines.splunk:splunk_windows_pipeline
```

### Docker

```
cd src
docker run --mount type=bind,source=[ipam data],target=/tmp/ -it py sigmascope.py
```

## Tests

```
cd src
uv run py.test
```

## About

sigmascope heavily leverages and appreciates `pysigma` for output generation.
