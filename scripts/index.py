import logging
import os
import shutil
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import yaml

from lib.aws_config_rule import AwsConfigRule, SeverityOverride
from lib.aws_docs_reader import generate_config_rule_data, generate_security_hub_controls_data
from lib.hcl_generator import generate_variables, generate_locals, load_source_file
from lib.rule_pack_info_generator import process_conformance_pack, InvalidConformancePackException

# Common constants.
CURRENT_DIR = Path(__file__).resolve().parent

# Managed rules constants.
ROOT_PAGE = 'https://docs.aws.amazon.com/config/latest/developerguide/'
AWS_MANAGED_RULES_PAGE = ROOT_PAGE + 'managed-rules-by-aws-config.html'
SECURITY_HUB_ROOT_PAGE = "https://docs.aws.amazon.com/securityhub/latest/userguide"
SECURITY_HUB_CONTROLS_REF_PAGE = "securityhub-controls-reference.html"
SOURCE_FILE_NAME = Path(CURRENT_DIR, 'config_rule_data.json')
SEVERITY_OVERRIDES_FILE_PATH = Path(CURRENT_DIR, '..', 'etc', 'severity_overrides.yaml').resolve()
SECURITY_HUB_CONTROLS_FILE_PATH = Path(CURRENT_DIR, 'security_hub_controls.json')
LOCALS_FILE_PATH = Path(CURRENT_DIR, '..', 'managed_rules_locals.tf').resolve()
VARIABLES_FILE_PATH = Path(CURRENT_DIR, '..', 'managed_rules_variables.tf').resolve()

# Rule packs generator constants.
RULES_DIR = 'aws-config-rules'
AWS_CONFIG_RULES_REPO = f'https://github.com/awslabs/{RULES_DIR}.git'
EXCLUDED_CONFORMANCE_PACKS = ('custom-conformance-pack',)
PACK_RULES_FILE = Path(CURRENT_DIR, '..', 'files', 'pack-rules.yaml')
PACKS_LIST_FILE = Path(CURRENT_DIR, '..', 'files', 'pack-rules-list.txt')

logging.basicConfig(
    level=logging.INFO,
    force=True,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt="%y-%m-%d %H:%M:%S")

def usage():
    print("\nUsage: python index.py <command>")

def update_config_rules():
    # Scrape AWS documentation for the latest Config Rules.
    generate_config_rule_data(
        root_url=ROOT_PAGE,
        managed_rules_page=AWS_MANAGED_RULES_PAGE,
        output_file=SOURCE_FILE_NAME)
    # Scrape AWS documentation for the latest Security Hub controls.
    generate_security_hub_controls_data(
        root_url=SECURITY_HUB_ROOT_PAGE,
        controls_ref_page=SECURITY_HUB_CONTROLS_REF_PAGE,
        output_file=SECURITY_HUB_CONTROLS_FILE_PATH)

    # Load the manual severity overrides.
    severity_overrides_data = load_source_file(SEVERITY_OVERRIDES_FILE_PATH)
    severity_overrides = [SeverityOverride(rule_name=k, data=v) for k, v in severity_overrides_data['overrides'].items()]

    # Load source file with the latest Config Rule definitions.
    latest_config_rules_data = load_source_file(SOURCE_FILE_NAME)

    # Update the list of managed rules with the corresponding severity levels
    # set by Security Hub controls.
    controls = load_source_file(SECURITY_HUB_CONTROLS_FILE_PATH)
    rules: List[AwsConfigRule] = []
    for rule_data in latest_config_rules_data:
        rule = AwsConfigRule(data=rule_data)
        for override in severity_overrides:
            if override.rule_name == rule.tf_rule_name:
                logging.info(f"Updating {rule.tf_rule_name} severity with override -> {override.severity}")
                rule.set_severity_level(override.severity)
                break
        for control in controls:
            if rule.tf_rule_name == control['rule']:
                logging.info(f"Updating {rule.tf_rule_name} severity -> {control['severity']}")
                rule.set_severity_level(control['severity'])
                break
        rules.append(rule)

    # Update the managed rules in the locals block with the latest changes.
    generate_locals(
        rules=rules,
        output_file=LOCALS_FILE_PATH)

    # Update the Config Rules parameters variables. We only want to create
    # variables for rules that have parameters.
    generate_variables(
        rules=[x for x in rules if x.parameters_data],
        output_file=VARIABLES_FILE_PATH)
    
def update_rule_packs():
    '''Unless $DOWNLOAD_CONFORMANCE_PACKS is explicitly set to something other than
    'yes', clone the git repository with the conformance packs.'''
    if os.environ.get('DOWNLOAD_CONFORMANCE_PACKS', 'yes') == 'yes':
        logging.info("Downloading conformance packs")
        if Path(RULES_DIR).exists():
            shutil.rmtree(RULES_DIR, ignore_errors=True)
        subprocess.run(['git', 'clone', AWS_CONFIG_RULES_REPO])

    yaml_files = sorted(list(Path.glob(Path(RULES_DIR, 'aws-config-conformance-packs'), '*.yaml')))
    rule_packs = []
    result = {
        'generated_on': datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        'packs': {}
    }

    # Load source file with the latest Config Rule definitions.
    latest_config_rules_data = load_source_file(SOURCE_FILE_NAME)
    config_rules: List[AwsConfigRule] = [AwsConfigRule(data=rule) for rule in latest_config_rules_data]

    for pack_file in yaml_files:
        try:
            pack, rules = process_conformance_pack(
                file_name=pack_file,
                excluded_packs=EXCLUDED_CONFORMANCE_PACKS,
                config_rules=config_rules)
        except InvalidConformancePackException:
            logging.warning(f"Skipping invalid conformance pack {pack_file}")
            continue
        result['packs'][pack] = rules
        rule_packs.append(pack)
        logging.info(f"Processed rule pack {pack}")

    logging.info(f"Writing rule packs to {PACK_RULES_FILE}")
    with PACK_RULES_FILE.open('w') as f:
        yaml.dump(result, f)

    logging.info(f"Writing rule packs list to {PACKS_LIST_FILE}")
    with PACKS_LIST_FILE.open('w') as f:
        f.write('\n'.join(rule_packs))

if __name__ == '__main__':
    valid_commands = ('update-config-rules', 'update-rule-packs',)
    try:
        cmd = sys.argv[1]
    except IndexError:
        logging.error("No command provided")
        logging.error(f"Valid commands: {', '.join(valid_commands)}")
        usage()
        exit(1)
    
    if cmd == 'update-config-rules':
        update_config_rules()
    elif cmd == 'update-rule-packs':
        update_rule_packs()
    else:
        logging.error(f"Invalid command: {cmd}")
        logging.error(f"Valid commands: {', '.join(valid_commands)}")
        usage()
        exit(1)