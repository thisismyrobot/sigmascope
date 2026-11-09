import textwrap

import sigmascope


def test_csv_load_good_data(caplog, net):
    assert sigmascope.load_networks_from_csv('tests/data/assigned.csv') == [
        net('10.0.0.1/32'),
        net('10.0.0.4/31')
    ]
    assert caplog.text == ''


def test_csv_load_mixed_quality_data_skips_bad_and_logs_issues(caplog, net):
    assert sigmascope.load_networks_from_csv('tests/data/mixed.csv') == [
        net('10.0.0.1/32'),
        net('10.0.0.4/31'),
        net('10.0.0.9/32'),
    ]
    assert caplog.text.strip() == textwrap.dedent("""
        WARNING  root:sigmascope.py:62 Unable to parse valid IPv4 network from first entry in row 1: ['heading', 'extra']
        WARNING  root:sigmascope.py:62 Unable to parse valid IPv4 network from first entry in row 4: []
        WARNING  root:sigmascope.py:62 Unable to parse valid IPv4 network from first entry in row 7: ['foo', 'bar']
        WARNING  root:sigmascope.py:62 Unable to parse valid IPv4 network from first entry in row 8: ['10.0.0', '', '']
        WARNING  root:sigmascope.py:62 Unable to parse valid IPv4 network from first entry in row 9: []
        WARNING  root:sigmascope.py:62 Unable to parse valid IPv4 network from first entry in row 10: []
    """).strip()
