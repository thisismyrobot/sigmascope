import textwrap

import sigmascope


def test_basic_sigma_rule(net):
    dark_nets = [
        net("10.0.0.0/32"),
        net("10.0.0.2/31"),
        net("10.0.0.6/31"),
        net("10.0.0.8/29"),
        net("10.0.0.16/28"),
        net("10.0.0.32/27"),
        net("10.0.0.64/26"),
        net("10.0.0.128/25"),
    ]
    rule_yaml = sigmascope.to_sigma(dark_nets, [])
    assert rule_yaml.strip() == textwrap.dedent("""
        title: SigmaScope search
        logsource:
          category: firewall
        detection:
          dark_networks:
            dst_ip|cidr:
            - 10.0.0.0/32
            - 10.0.0.2/31
            - 10.0.0.6/31
            - 10.0.0.8/29
            - 10.0.0.16/28
            - 10.0.0.32/27
            - 10.0.0.64/26
            - 10.0.0.128/25
          condition: dark_networks
    """).strip()


def test_sigma_rule_with_allowed_sources(net):
    dark_nets = [
        net("10.0.0.0/32"),
        net("10.0.0.2/31"),
        net("10.0.0.6/31"),
        net("10.0.0.8/29"),
        net("10.0.0.16/28"),
        net("10.0.0.32/27"),
        net("10.0.0.64/26"),
        net("10.0.0.128/25"),
    ]
    allowed_sources = [net("10.0.1.2/32")]
    rule_yaml = sigmascope.to_sigma(dark_nets, allowed_sources)
    assert rule_yaml.strip() == textwrap.dedent("""
        title: SigmaScope search
        logsource:
          category: firewall
        detection:
          dark_networks:
            dst_ip|cidr:
            - 10.0.0.0/32
            - 10.0.0.2/31
            - 10.0.0.6/31
            - 10.0.0.8/29
            - 10.0.0.16/28
            - 10.0.0.32/27
            - 10.0.0.64/26
            - 10.0.0.128/25
          condition: dark_networks and not allowed_sources
          allowed_sources:
            src_ip|cidr:
            - 10.0.1.2/32
    """).strip()
