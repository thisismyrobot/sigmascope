import argparse
import csv
import ipaddress
import logging
import subprocess
import sys

import yaml

logger = logging.getLogger(__name__)


class SigmaExecutionException(Exception):
    pass


def to_sigma(
    dark_networks: list[ipaddress.IPv4Network],
    allowed_source_nets: list[ipaddress.IPv4Network],
) -> str:
    # Need to work out correct fields to align with Splunk Common Information Model (CIM)
    rule_data: dict = {
        "title": "SigmaScope search",
        "logsource": {"category": "firewall"},
        "detection": {
            "dark_networks": {
                "dst_ip": [network.exploded for network in dark_networks]
            },
            "condition": "dark_networks",
        },
    }
    if allowed_source_nets:
        rule_data["detection"]["allowed_sources"] = {
            "src_ip": [network.exploded for network in allowed_source_nets]
        }
        rule_data["detection"]["condition"] += " and not allowed_sources"
    return yaml.safe_dump(rule_data, sort_keys=False)


def dark_networks(
    reserved: list[ipaddress.IPv4Network], assigned: list[ipaddress.IPv4Network]
) -> list[ipaddress.IPv4Network]:
    reserved_dark = list(reserved)
    for assigned_net in assigned:
        expanded_reserved: list[ipaddress.IPv4Network] = []
        for reserved_net in reserved_dark:
            if assigned_net.subnet_of(reserved_net):
                expanded_reserved.extend(reserved_net.address_exclude(assigned_net))
            else:
                expanded_reserved.append(reserved_net)
        reserved_dark = list(ipaddress.collapse_addresses(expanded_reserved))
    return reserved_dark


def load_networks_from_csv(csv_file: str) -> list[ipaddress.IPv4Network]:
    ipv4_networks = []
    with open(csv_file, "r") as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            try:
                ipv4_networks.append(ipaddress.IPv4Network(row[0].strip()))
            except (IndexError, ValueError) as _:
                logger.warning(
                    f"Unable to parse valid IPv4 network from first entry in row {i+1}: {row}"
                )
        return list(ipaddress.collapse_addresses(ipv4_networks))


def run_conversion(
    backend: str,
    pipelines: list[str],
    sigma_rule_yaml: str,
    use_global_sigma: bool = False,
) -> str:
    sigma = ["sigma"] if use_global_sigma else ["uv", "run", "sigma"]
    command = [
        *sigma,
        "convert",
        "--pipeline-check",
        "--verbose",
        "-t",
        backend,
    ]
    for pipeline in pipelines:
        command.extend(["-p", pipeline])
    command.append("-")
    result = subprocess.run(
        command,
        check=False,
        input=sigma_rule_yaml,
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        raise SigmaExecutionException(
            f"Failed to run conversion pipeline, with error: {result.stderr}"
        )


def main(
    assigned_nets: list[ipaddress.IPv4Network],
    reserved_nets: list[ipaddress.IPv4Network],
    allowed_nets: list[ipaddress.IPv4Network],
    target_spec: str,
    pipeline: list[str],
    use_global_sigma: bool = False,
) -> str:
    dark_nets = dark_networks(assigned_nets, reserved_nets)
    sigma_rule_yaml = to_sigma(dark_nets, allowed_nets)
    query = run_conversion(target_spec, pipeline, sigma_rule_yaml, use_global_sigma)
    return query


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "reserved_file",
        help="CSV file of reserved IP addresses and ranges (in CIDR notation)",
    )
    parser.add_argument(
        "assigned_file",
        help="CSV file of assigned IP addresses and ranges (in CIDR notation)",
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Name of target sigma.backend module - e.g., 'splunk'",
    )
    parser.add_argument(
        "-p",
        "--pipeline",
        required=True,
        action="append",
        help="Name of sigma.pipelines module - e.g., 'splunk_cim', or path to a pipeline YAML definition",
    )

    parser.add_argument(
        "--allowed_sources_file",
        help="CSV file of known-good allowed source addresses (e.g., internal scanners)",
        default=None,
    )

    parser.add_argument(
        "--global-sigma",
        help="Use a globally-installed sigma-cli instance instead of the bundled version",
        default=False,
    )

    args = parser.parse_args()
    query = main(
        load_networks_from_csv(args.reserved_file),
        load_networks_from_csv(args.assigned_file),
        (
            load_networks_from_csv(args.allowed_sources_file)
            if args.allowed_sources_file
            else []
        ),
        args.target,
        args.pipeline,
        args.global_sigma,
    )
    sys.stdout.write(query)
