import json

from pathlib import Path
from typing import List

from lib.aws_config_rule import AwsConfigRule

from jinja2 import Environment, PackageLoader, select_autoescape
from python_terraform import Terraform

def generate_variables(rules: List[AwsConfigRule], output_file: Path) -> None:
    """Takes an input file with a list of AWS-managed Config Rules and
    generates HCL code from the list."""
    print("Creating Terraform variables for AWS-managed Config Rules.")
    env = Environment(
        loader=PackageLoader("index"),
        autoescape=select_autoescape())
    template = env.get_template("variable.jinja")

    result = []
    for rule in rules:
        result.append(template.render(config=rule))

    with Path(output_file).open('w') as f:
        f.write('\n\n'.join(result))

    format_hcl()

def generate_locals(rules: List[AwsConfigRule], output_file: Path) -> None:
    """Create the managed_rules_locals `locals` block and write it to disk."""
    print("Creating Terraform locals block for AWS-managed Config Rules.")
    env = Environment(
        loader=PackageLoader("index"),
        autoescape=select_autoescape())
    template = env.get_template("locals_block.jinja")

    result = template.render(rules=rules)

    with Path(output_file).open('w') as f:
        f.write(result)

    format_hcl()

def load_source_file(file_name: Union[Path, str]) -> dict:
    """Return a map of rule definitions."""
    # Load using JSON or YAML based on the file extension.
    with Path(file_name).open() as f:
        if file_name.suffix in ('.yml', '.yaml',):
            data = yaml.safe_load(f)
        elif file_name.suffix == '.json':
            data = json.loads(f.read())
        else:
            raise ValueError(f"Unsupported file extension: {file_name.suffix}")
    return data

def format_hcl() -> None:
    """Format Terraform files with `terraform fmt`."""
    t = Terraform()
    return_code, stdout, stderr = t.cmd('fmt', '../../.')
