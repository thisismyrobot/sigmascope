import ipaddress

import sigmascope


def test_to_splunk_cim_using_yaml_pipeline(net):
    reserved_nets = [net('10.0.0.0/28')]
    assigned_nets = [
        net('10.0.0.1'),
        net('10.0.0.4'),
        net('10.0.0.5'),
    ]
    cim_search = sigmascope.main(
        reserved_nets,
        assigned_nets,
        [],
        target_spec=('sigma.backends.splunk', 'SplunkBackend'),
        pipeline_spec='pipelines/splunk_cim_firewall_logs.yaml'
    )

    assert cim_search == 'dest_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'


def test_to_splunk_cim_using_module_pipeline(net):
    reserved_nets = [net('10.0.0.0/28')]
    assigned_nets = [
        net('10.0.0.1'),
        net('10.0.0.4'),
        net('10.0.0.5'),
    ]
    cim_search = sigmascope.main(
        reserved_nets,
        assigned_nets,
        [],
        target_spec=('sigma.backends.splunk', 'SplunkBackend'),

        # Chosen data model is a no-op in this context, this tests it loads though.
        pipeline_spec=('sigma.pipelines.splunk', 'splunk_windows_pipeline')
    )

    # The output here isn't what's useful for Splunk, but it is proof the module loaded and ran.
    assert cim_search == 'dst_ip IN ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'
