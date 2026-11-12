import subprocess
import textwrap


def test_help_invocation():
    help_text = subprocess.run(
        ["uv", "run", "sigmascope.py"], check=False, capture_output=True, text=True
    ).stderr

    assert help_text.strip() == textwrap.dedent("""
        usage: sigmascope.py [-h] -b BACKEND -p PIPELINE
                             [--allowed_source_nets ALLOWED_SOURCE_NETS]
                             reserved_csv assigned_csv
        sigmascope.py: error: the following arguments are required: reserved_csv, assigned_csv, -b/--backend, -p/--pipeline
    """).strip()


def test_pipeline_module_invocation():
    result = subprocess.run(
        [
            "uv",
            "run",
            "sigmascope.py",
            "-b",
            "splunk",
            "-p",
            "splunk_windows",
            "tests/data/reserved.csv",
            "tests/data/assigned.csv",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stderr == ""

    query_text = result.stdout
    assert (
        query_text.strip()
        == 'dst_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'
    )


def test_pipeline_file_invocation():
    result = subprocess.run(
        [
            "uv",
            "run",
            "sigmascope.py",
            "-b",
            "splunk",
            "-p",
            "pipelines/splunk_cim_firewall_logs.yaml",
            "tests/data/reserved.csv",
            "tests/data/assigned.csv",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stderr == ""

    query_text = result.stdout
    assert (
        query_text.strip()
        == 'dest_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'
    )


def test_pipeline_invocation_with_allowed_sources():
    result = subprocess.run(
        [
            "uv",
            "run",
            "sigmascope.py",
            "-b",
            "splunk",
            "-p",
            "pipelines/splunk_cim_firewall_logs.yaml",
            "--allowed_source_nets=tests/data/allowed.csv",
            "tests/data/reserved.csv",
            "tests/data/assigned.csv",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stderr == ""

    query_text = result.stdout
    assert (
        query_text.strip()
        == 'dest_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29") NOT (src_ip IN ("10.0.1.2/32", "10.0.4.0/29"))'
    )
