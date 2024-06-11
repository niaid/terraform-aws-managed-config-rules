#!/usr/bin/env python

'''Download conformance packs, parse them and produce two files:
    - A YAML file containing all of the Config Rules associated with each pack
    - A text file containing only a newline separated list of all the packs'''

import logging

from pathlib import Path
from typing import List, Tuple, Union

import yaml

from lib.aws_config_rule import AwsConfigRule

class NoSourcePropertyException(Exception):
    """The 'Source' property of a Rule is missing."""
    pass


class InvalidConformancePackException(Exception):
    """The conformance pack should be excluded from the list."""
    pass


def get_resource_source_identifier(resource: dict) -> str:
    """Get a rule's SourceIdentifier property.

    Expects a dict with the following structure:
    {
        'EXAMPLE_RULE': {
            'Properties': {
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'EXAMPLE_IDENTIFIER'
                }
            }
        }
    }
    
    Args:
        resource (dict): A CloudFormation Resource definition.
    
    Returns:
        A rule's SourceIdentifier property.
        
    Exception:
        NoSourcePropertyException: Raised when a rule is missing a 'Source'
            property."""
    if resource['Properties'].get('Source', None) is None:
        raise NoSourcePropertyException
    return resource['Properties']['Source']['SourceIdentifier']

def load_conformance_pack_yaml(path: Union[Path, str]) -> dict:
    with Path(path).open() as f:
        return yaml.safe_load(f.read())
    
def format_identifier(identifier: str) -> str:
    return identifier.lower().replace('_', '-')

def process_conformance_pack(
        file_name: str,
        excluded_packs: List[str],
        config_rules: List[AwsConfigRule]) -> Tuple[str, List[str]]:
    yaml_file = Path(file_name)
    pack = yaml_file.stem

    if pack in excluded_packs:
        raise InvalidConformancePackException

    content = load_conformance_pack_yaml(yaml_file)
    rules = []
    for rule, attr in content['Resources'].items():
        try:
            identifier = get_resource_source_identifier(attr)
            for config_rule in config_rules:
                if config_rule.rule_identifier == identifier:
                    new_identifier = config_rule.tf_rule_name
                    break
            if new_identifier not in rules:
                rules.append(new_identifier)
        except NoSourcePropertyException:
            logging.warning(f"Rule '{rule}' in pack {pack} has no 'Source' property. Skipping")
            continue

    return pack, sorted(rules)
