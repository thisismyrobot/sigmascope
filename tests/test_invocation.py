import subprocess
import textwrap


def test_help_invocation():
    help_text = subprocess.run(['uv', 'run', 'sigmascope.py'], capture_output=True, text=True).stderr

    assert help_text.strip() == textwrap.dedent("""
        usage: sigmascope.py [-h] [--allowed_source_nets ALLOWED_SOURCE_NETS]
                             reserved_csv assigned_csv target_spec pipeline_spec
        sigmascope.py: error: the following arguments are required: reserved_csv, assigned_csv, target_spec, pipeline_spec
    """).strip()


def test_pipeline_module_invocation():
    result = subprocess.run([
        'uv',
        'run',
        'sigmascope.py',
        'tests/data/reserved.csv',
        'tests/data/assigned.csv',
        'sigma.backends.splunk:SplunkBackend',
        'sigma.pipelines.splunk:splunk_windows_pipeline'
    ], capture_output=True, text=True)
    assert result.stderr == ''

    query_text = result.stdout
    assert query_text.strip() == 'dst_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'


def test_pipeline_file_invocation():
    result = subprocess.run([
        'uv',
        'run',
        'sigmascope.py',
        'tests/data/reserved.csv',
        'tests/data/assigned.csv',
        'sigma.backends.splunk:SplunkBackend',
        'pipelines/splunk_cim_firewall_logs.yaml'
    ], capture_output=True, text=True)
    assert result.stderr == ''

    query_text = result.stdout
    assert query_text.strip() == 'dest_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'


def test_pipeline_invocation_with_allowed_sources():
    result = subprocess.run([
        'uv',
        'run',
        'sigmascope.py',
        'tests/data/reserved.csv',
        'tests/data/assigned.csv',
        'sigma.backends.splunk:SplunkBackend',
        'pipelines/splunk_cim_firewall_logs.yaml',
        '--allowed_source_nets=tests/data/allowed.csv'
    ], capture_output=True, text=True)
    assert result.stderr == ''

    query_text = result.stdout
    assert query_text.strip() == 'dest_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29") NOT (src_ip IN ("10.0.1.2/32", "10.0.4.0/29"))'
