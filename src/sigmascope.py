import ipaddress

import sigma.rule
import sigma.validation
import sigma.validators.core
import yaml


def to_sigma(networks):
    rule_data = {
        'title': 'SigmaScope search',
        'logsource': {
            'category': 'network',
            'service': 'connection'
        },
        'detection': {
            'selection': {
                'DestinationIp|cidr': [network.exploded for network in networks]
            },
            'condition': 'selection'
        }
    }

    validator = sigma.validation.SigmaValidator.from_dict({'validators':['all']}, sigma.validators.core.validators)
    rule = sigma.rule.SigmaRule.from_dict(rule_data)
    validator.validate_rule(rule)

    return yaml.safe_dump(rule_data, sort_keys=False)


def main():
    networks = map(ipaddress.ip_network, [
        '192.168.0.0/28',
        '192.0.2.0/25',
        '192.0.2.128/25',
        '10.0.0.0/8'
    ])
    networks = ipaddress.collapse_addresses(networks)
    sigma_rule = to_sigma(networks)
    with open('sigma.yaml', 'w') as f:
        f.write(sigma_rule)


if __name__ == '__main__':
    main()
