import argparse
import collections
import csv
import importlib
import ipaddress
import logging
import sys

import sigma.collection
import sigma.processing.pipeline
import sigma.validators.core
import yaml


def to_sigma(dark_networks, allowed_source_nets):
    # Need to work out correct fields to align with Splunk Common Information Model (CIM)
    rule_data = {
        'title': 'SigmaScope search',
        'logsource': {
            'category': 'firewall'
        },
        'detection': {
            'dark_networks': {
                'dst_ip': [network.exploded for network in dark_networks]
            },
            'condition': 'dark_networks'
        }
    }
    if allowed_source_nets:
        rule_data['detection']['allowed_sources'] = {'src_ip': [network.exploded for network in allowed_source_nets]}
        rule_data['detection']['condition'] += ' and not allowed_sources'
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


def load_networks_from_csv(csv_file) -> list[ipaddress.IPv4Network]:
    ipv4_networks = []
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        for (i, row) in enumerate(reader):
            try:
                ipv4_networks.append(ipaddress.IPv4Network(row[0].strip()))
            except IndexError, ValueError:
                logging.warning(f'Unable to parse valid IPv4 network from first entry in row {i+1}: {row}')
        return list(ipaddress.collapse_addresses(ipv4_networks))


def load_backend(target_spec, pipeline_spec):
    # Load or create pipeline
    pipeline = None
    if isinstance(pipeline_spec, str):
        if pipeline_spec.endswith('.yaml'):
            with open(pipeline_spec, 'r') as f:
                pipeline = sigma.processing.pipeline.ProcessingPipeline.from_yaml(f.read())
    elif isinstance(pipeline_spec, collections.abc.Iterable):
        try:
            pipeline_mod_path, factory = pipeline_spec
        except ValueError:
            raise ValueError(f'Unable to parse pipeline module and factory path from: {pipeline_spec}')
        try:
            pipeline_module = importlib.import_module(pipeline_mod_path)
        except ModuleNotFoundError:
            raise ValueError(f'Pipeline module {pipeline_mod_path} could not be imported')
        try:
            pipeline = getattr(pipeline_module, factory)()
        except AttributeError:
            raise ValueError(f'Pipeline module {pipeline_mod_path} does not have the factory {factory}')

    if pipeline is None:
        raise ValueError(f'Failed to load a module or file based on the pipeline spec: {pipeline_spec}')

    # Load backend
    try:
        backend_mod_path, cls = target_spec
    except ValueError:
        raise ValueError(f'Unable to parse backend module and class path from: {target_spec}')

    try:
        backend_module = importlib.import_module(backend_mod_path)
    except ModuleNotFoundError:
        raise ValueError(f'Backend module {backend_mod_path} could not be imported')

    try:
        constructor = getattr(backend_module, cls)
    except AttributeError:
        raise ValueError(f'Backend module {backend_mod_path} does not have the class {cls}')

    return constructor(pipeline)


def main(assigned_nets, reserved_nets, allowed_nets, target_spec, pipeline_spec, output_path=None):
    dark_nets = dark_networks(assigned_nets, reserved_nets)
    sigma_rule_yaml = to_sigma(dark_nets, allowed_nets)
    sigma_rule_collection = sigma.collection.SigmaCollection.from_yaml(sigma_rule_yaml)
    backend = load_backend(target_spec, pipeline_spec)
    query = backend.convert(sigma_rule_collection)[0]
    return query


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('reserved_csv', help='CSV file of reserved IP addresses and ranges (in CIDR notation)')
    parser.add_argument('assigned_csv', help='CSV file of assigned IP addresses and ranges (in CIDR notation)')
    parser.add_argument('target_spec', help='sigma.backends.[module]:[constructor]')
    parser.add_argument('pipeline_spec', help='sigma.pipelines.[module]:[constructor] or pass a pipeline YAML file path')
    parser.add_argument('--allowed_source_nets', help='CSV file of known-good allowed source addresses (e.g., internal scanners)', default=None)
    args = parser.parse_args()
    query = main(
        load_networks_from_csv(args.reserved_csv),
        load_networks_from_csv(args.assigned_csv),
        (load_networks_from_csv(args.allowed_source_nets) if args.allowed_source_nets else []),
        args.target_spec.split(':'),
        args.pipeline_spec if ':' not in args.pipeline_spec else args.pipeline_spec.split(':')
    )
    sys.stdout.write(query)
