import argparse
import importlib
import ipaddress
import sys

import sigma.collection
import sigma.processing.pipeline
import sigma.rule
import sigma.validation
import sigma.validators.core
import yaml


def to_sigma(networks):
    # Need to work out correct fields to align with Splunk Common Information Model (CIM)
    rule_data = {
        'title': 'SigmaScope search',
        'logsource': {
            'category': 'firewall'
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


def load_backend(target_spec, pipeline_spec):
    # Load or create pipeline
    pipeline = None
    try:
        mod_path, factory = pipeline_spec
        pipeline_module = importlib.import_module(mod_path)
        pipeline = getattr(pipeline_module, factory)()
    except ValueError:
        if pipeline_spec.endswith('.yaml'):
            with open(pipeline_spec, 'r') as f:
                pipeline = sigma.processing.pipeline.ProcessingPipeline.from_yaml(f.read())

    if pipeline is None:
        raise Exception(f'Failed to load a module or file based on the pipeline spec: {pipeline_spec}')

    # Load backend
    backend_module = importlib.import_module(target_spec[0])
    backend = getattr(backend_module, target_spec[1])(pipeline)
    return backend


def main(assigned_nets, reserved_nets, allowed_nets, target_spec, pipeline_spec, output_path=None):
    dark_nets = dark_networks(assigned_nets, reserved_nets)
    sigma_rule_yaml = to_sigma(dark_nets)
    sigma_rule_collection = sigma.collection.SigmaCollection.from_yaml(sigma_rule_yaml)
    backend = load_backend(target_spec, pipeline_spec)
    query = backend.convert(sigma_rule_collection)[0]
    return query


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('reserved_csv')
    parser.add_argument('assigned_csv')
    parser.add_argument('target_spec', help='sigma.backends.[module]:[constructor]')
    parser.add_argument('pipeline_spec', help='Pass a pipeline YAML file path or sigma.pipelines.[module]:[constructor]')
    parser.add_argument('--allowed_csv', default=None)
    args = parser.parse_args()
    query = main(
        load_networks_from_csv(args.reserved_csv),
        load_networks_from_csv(args.assigned_csv),
        (load_networks_from_csv(args.allowed_csv) if args.allowed_csv else []),
        args.target_spec.split(':'),
        args.pipeline_spec if ':' not in args.pipeline_spec else args.pipeline_spec.split(':')
    )
    sys.stdout.write(query)
