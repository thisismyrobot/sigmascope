import sigmascope


def test_to_defender_xdr(net):
    reserved_nets = [net('10.0.0.0/28')]
    assigned_nets = [
        net('10.0.0.1'),
        net('10.0.0.4'),
        net('10.0.0.5'),
    ]
    xdr_filter = sigmascope.main(
        reserved_nets,
        assigned_nets,
        [],
        target_spec=('sigma.backends.kusto', 'KustoBackend'),
        pipeline_spec='pipelines/defender_xdr.yaml'
    )

    assert xdr_filter == 'RemoteIP in~ ("10.0.0.0/32", "10.0.0.2/31", "10.0.0.6/31", "10.0.0.8/29")'
