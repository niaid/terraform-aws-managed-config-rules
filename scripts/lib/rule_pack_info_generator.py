#!/usr/bin/env python

'''Download conformance packs, parse them and produce two files:
    - A YAML file containing all of the Config Rules associated with each pack
    - A text file containing only a newline separated list of all the packs'''

import logging
import os
import shutil
import subprocess

from datetime import datetime, timezone

from pathlib import Path
from typing import List, Union

import yaml

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - RulePackGenerator - [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')

RULES_DIR = 'aws-config-rules'
AWS_CONFIG_RULES_REPO = f'https://github.com/awslabs/{RULES_DIR}.git'
EXCLUDED_CONFORMANCE_PACKS = ('custom-conformance-pack',)

'''Unless $DOWNLOAD_CONFORMANCE_PACKS is explicitly set to something other than
'yes', clone the git repository with the conformance packs.'''
if os.environ.get('DOWNLOAD_CONFORMANCE_PACKS', 'yes') == 'yes':
    logging.info("Downloading conformance packs")
    if Path(RULES_DIR).exists():
        shutil.rmtree(RULES_DIR, ignore_errors=True)
    subprocess.run(['git', 'clone', AWS_CONFIG_RULES_REPO])

YAML_FILES = sorted(list(Path.glob(Path(RULES_DIR, 'aws-config-conformance-packs'), '*.yaml')))
PACK_RULES_FILE = Path('..', '..', 'files', 'pack-rules.yaml')
PACKS_LIST_FILE = Path('..', '..', 'files', 'pack-rules-list.txt')

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

def write_pack_rules_yaml(file_name: Union[Path, str], data: dict) -> None:
    with Path(file_name).open('w') as f:
        yaml.dump(data, f)

def write_packs_list(file_name: Union[Path, str], packs: List[str]) -> None:
    with Path(file_name).open('w') as f:
        f.write('\n'.join(packs))

def process_conformance_pack(file_name: str) -> dict:
    yaml_file = Path(file_name)
    pack = yaml_file.stem

    if pack in EXCLUDED_CONFORMANCE_PACKS:
        raise InvalidConformancePackException

    content = load_conformance_pack_yaml(yaml_file)
    rules = []
    for rule, attr in content['Resources'].items():
        try:
            identifier = get_resource_source_identifier(attr)
            new_identifier = format_identifier(identifier)
            if new_identifier not in rules:
                rules.append(new_identifier)
        except NoSourcePropertyException:
            logging.warning(f"Rule '{rule}' in pack {pack} has no 'Source' property. Skipping")
            continue

    return pack, sorted(rules)

def main():
    rule_packs = []
    result = {
        'generated_on': datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        'packs': {}
    }

    for f in YAML_FILES:
        try:
            pack, rules = process_conformance_pack(file_name=f)
        except InvalidConformancePackException:
            continue
        result['packs'][pack] = rules
        rule_packs.append(pack)
        logging.info(f"Processed rule pack {pack}")

    write_pack_rules_yaml(file_name=PACK_RULES_FILE, data=result)
    write_packs_list(file_name=PACKS_LIST_FILE, packs=rule_packs)

if __name__ == '__main__':
    main()