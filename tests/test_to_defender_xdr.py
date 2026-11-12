import sigmascope


def test_defender_xdr_yaml_pipeline_expands_remote_ip_list(net):
    reserved_nets = [net("10.0.0.0/28")]
    assigned_nets = [net("10.0.0.1")]
    allowed_source_nets = [net("10.0.0.9")]
    xdr_filter = sigmascope.main(
        reserved_nets,
        assigned_nets,
        allowed_source_nets,
        target_spec="kusto",
        pipeline=["pipelines/defender_xdr.yaml"],
    )

    assert (
        xdr_filter
        == '(ipv4_is_in_any_range(RemoteIP, "10.0.0.0/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/29")) and (not(LocalIP =~ "10.0.0.9"))'
    )


def test_defender_xdr_yaml_pipeline_simple_handles_single_ip_range(net):
    reserved_nets = [net("10.0.0.0/28")]
    assigned_nets = []
    allowed_source_nets = [net("10.1.0.0/27")]
    xdr_filter = sigmascope.main(
        reserved_nets,
        assigned_nets,
        allowed_source_nets,
        target_spec="kusto",
        pipeline=["pipelines/defender_xdr.yaml"],
    )

    assert (
        xdr_filter
        == 'ipv4_is_in_range(RemoteIP, "10.0.0.0/28") and (not(ipv4_is_in_range(LocalIP, "10.1.0.0/27")))'
    )


def test_defender_xdr_yaml_pipeline_simple_handles_single_ip(net):
    reserved_nets = [net("10.0.0.0")]
    assigned_nets = []
    allowed_source_nets = [net("10.0.0.2/32")]
    xdr_filter = sigmascope.main(
        reserved_nets,
        assigned_nets,
        allowed_source_nets,
        target_spec="kusto",
        pipeline=["pipelines/defender_xdr.yaml"],
    )

    assert xdr_filter == 'RemoteIP =~ "10.0.0.0" and (not(LocalIP =~ "10.0.0.2"))'


def test_defender_xdr_yaml_pipeline_complex(net):
    reserved_nets = [net("10.0.0.0/28")]
    assigned_nets = [
        net("10.0.0.1"),
        net("10.0.0.4"),
        net("10.0.3.3"),
    ]
    allowed_source_nets = [net("10.0.0.9"), net("10.1.0.0/23")]
    xdr_filter = sigmascope.main(
        reserved_nets,
        assigned_nets,
        allowed_source_nets,
        target_spec="kusto",
        pipeline=["pipelines/defender_xdr.yaml"],
    )

    assert (
        xdr_filter
        == '(ipv4_is_in_any_range(RemoteIP, "10.0.0.0/32", "10.0.0.2/31", "10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/29")) and (not((ipv4_is_in_any_range(LocalIP, "10.0.0.9/32", "10.1.0.0/23"))))'
    )


def test_defender_xdr_chained_pipeline(net):
    reserved_nets = [net("10.0.0.0/28")]
    assigned_nets = [net("10.0.0.1")]
    allowed_source_nets = [net("10.0.0.9"), net("10.2.1.0/25")]
    xdr_filter = sigmascope.main(
        reserved_nets,
        assigned_nets,
        allowed_source_nets,
        target_spec="kusto",
        pipeline=["pipelines/defender_xdr.yaml", "microsoft_xdr"],
    )

    assert (
        xdr_filter
        == 'DeviceNetworkEvents\n| where (ipv4_is_in_any_range(RemoteIP, "10.0.0.0/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/29")) and (not((ipv4_is_in_any_range(LocalIP, "10.0.0.9/32", "10.2.1.0/25"))))'
    )
