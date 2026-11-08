# SigmaScope: Network telescope/IP darknet rule generator

Converts IPAM information sets into SIEM queries, via Sigma.

## Requirements

Python 3.14+ + `uv`, or docker

## Setup

### Python

Add output format packages (choose from `splunk`, ... TODO):

`uv sync --extra splunk`

## Run

### Docker

```
cd src
docker run --mount type=bind,source=[ipam data],target=/tmp/ -it py sigmascope.py
```

### Python

```
cd src
uv run sigmascope.py [reservations CSV file] [assigned CSV file] [threshold] [format spec]
```

## About

sigmascope heavily leverages and appreciates `pysigma` for output generation.
