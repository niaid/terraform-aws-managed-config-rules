from pathlib import Path
from typing import List

from lib.aws_config_rule import AwsConfigRule
from lib.aws_docs_reader import generate_config_rule_data
from lib.hcl_generator import generate_variables, generate_locals, load_source_file
from lib.hcl_reader import read_hcl_file

ROOT_PAGE = 'https://docs.aws.amazon.com/config/latest/developerguide/'
AWS_MANAGED_RULES_PAGE = ROOT_PAGE + 'managed-rules-by-aws-config.html'
SOURCE_FILE_NAME = Path('config_rule_data.json')
LOCALS_FILE_PATH = Path('..', '..', 'managed_rules_locals.tf')
VARIABLES_FILE_PATH = Path('..', '..', 'managed_rules_variables.tf')

if __name__ == '__main__':
    # Scrape AWS documentation for the latest Config Rules.
    generate_config_rule_data(
        root_url=ROOT_PAGE,
        managed_rules_page=AWS_MANAGED_RULES_PAGE)

    # Load the list of managed rules from the existing locals block.
    data = read_hcl_file(LOCALS_FILE_PATH)
    existing_rules_data = None
    for _, local in enumerate(data['locals']):
        existing_rules_data = local['managed_rules']

    # Load source file with the latest Config Rule definitions.
    latest_config_rules_data = load_source_file(SOURCE_FILE_NAME)

    # Update the severity levels of the latest rules from the existing rules.
    rules: List[AwsConfigRule] = []
    existing_rules = existing_rules_data.keys()
    for rule_data in latest_config_rules_data:
        rule = AwsConfigRule(data=rule_data)
        if rule.name not in existing_rules:
            rules.append(rule)
            continue
        for existing_rule_name, existing_rule_data in existing_rules_data.items():
            if rule.name == existing_rule_name:
                print(f"Updating rule {rule.name} severity to {existing_rule_data['severity']}")
                rule.set_severity_level(existing_rule_data['severity'])
                rules.append(rule)
                break

    # Update the managed rules in the locals block with the latest changes.
    generate_locals(
        rules=rules,
        output_file=LOCALS_FILE_PATH)

    # Update the Config Rules parameters variables. We only want to create
    # variables for rules that have parameters.
    generate_variables(
        rules=[x for x in rules if x.parameters_data],
        output_file=VARIABLES_FILE_PATH)
