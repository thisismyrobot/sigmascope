import sys; sys.path.insert(0, '.')
import ipaddress

import pytest


@pytest.fixture(scope='function')
def net():
    def net_factory(net_str):
        return ipaddress.ip_network(net_str)
    return net_factory
