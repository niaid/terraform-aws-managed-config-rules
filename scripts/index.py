import logging

from pathlib import Path
from typing import List

from lib.aws_config_rule import AwsConfigRule, SeverityOverride
from lib.aws_docs_reader import generate_config_rule_data, generate_security_hub_controls_data
from lib.hcl_generator import generate_variables, generate_locals, load_source_file

ROOT_PAGE = 'https://docs.aws.amazon.com/config/latest/developerguide/'
AWS_MANAGED_RULES_PAGE = ROOT_PAGE + 'managed-rules-by-aws-config.html'
SECURITY_HUB_ROOT_PAGE = "https://docs.aws.amazon.com/securityhub/latest/userguide"
SECURITY_HUB_CONTROLS_REF_PAGE = "securityhub-controls-reference.html"
CURRENT_DIR = Path(__file__).resolve().parent
SOURCE_FILE_NAME = Path(CURRENT_DIR, 'config_rule_data.json')
SEVERITY_OVERRIDES_FILE_PATH = Path(CURRENT_DIR, '..', 'etc', 'severity_overrides.yaml').resolve()
SECURITY_HUB_CONTROLS_FILE_PATH = Path(CURRENT_DIR, 'security_hub_controls.json')
LOCALS_FILE_PATH = Path(CURRENT_DIR, '..', 'managed_rules_locals.tf').resolve()
VARIABLES_FILE_PATH = Path(CURRENT_DIR, '..', 'managed_rules_variables.tf').resolve()

logging.basicConfig(
    level=logging.INFO,
    force=True,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt="%y-%m-%d %H:%M:%S")


if __name__ == '__main__':
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
            if override.rule_name == rule.name:
                logging.info(f"Updating {rule.name} severity with override -> {override.severity}")
                rule.set_severity_level(override.severity)
                break
        for control in controls:
            if rule.name == control['rule']:
                logging.info(f"Updating {rule.name} severity -> {control['severity']}")
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
