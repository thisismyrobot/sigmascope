import argparse
import ipaddress

import sigma.rule
import sigma.validation
import sigma.validators.core
import yaml


def to_sigma(networks):
    # Need to work out correct fields to align with Splunk Common Information Model (CIM)
    rule_data = {
        'title': 'SigmaScope search',
        'logsource': {
            'category': 'network',
            'service': 'connection'
        },
        'detection': {
            'selection': {
                'dst_ip': [network.exploded for network in networks]
            },
            'condition': 'selection'
        }
    }

    validator = sigma.validation.SigmaValidator.from_dict({'validators':['all']}, sigma.validators.core.validators)
    rule = sigma.rule.SigmaRule.from_dict(rule_data)
    validator.validate_rule(rule)
    return yaml.safe_dump(rule_data, sort_keys=False)


def dark_networks(reserved, assigned):
    reserved_dark = list(reserved)
    for assigned_net in assigned:
        expanded_reserved = []
        for reserved_net in reserved_dark:
            if assigned_net.subnet_of(reserved_net):
                expanded_reserved.extend(reserved_net.address_exclude(assigned_net))
            else:
                expanded_reserved.append(reserved_net)
        reserved_dark = ipaddress.collapse_addresses(expanded_reserved)
    return reserved_dark


def load_networks_from_csv(csv_file):
    with open(csv_file, 'r') as f:
        networks = [ipaddress.ip_network(line.strip())
                    for line
                    in f
                    if line.strip() != '']
        return list(ipaddress.collapse_addresses(networks))


def main(assigned_nets, reserved_nets, allowed_nets, target, pipeline):
    dark_nets = dark_networks(assigned_nets, reserved_nets)
    sigma_rule = to_sigma(dark_nets)
    return sigma_rule
    with open('sigma.yaml', 'w') as f:
        f.write(sigma_rule)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('reserved_csv')
    parser.add_argument('assigned_csv')
    parser.add_argument('--allowed_csv', default=None)
    args = parser.parse_args()
    main(
        load_networks_from_csv(args.reserved_csv),
        load_networks_from_csv(args.assigned_csv),
        (load_networks_from_csv(args.allowed_csv) if args.allowed_csv else []),
    )
