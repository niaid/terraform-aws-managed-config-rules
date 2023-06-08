from pathlib import Path

import hcl2

def read_hcl_file(file_name: str) -> dict:
    """Read a Terraform HCL file and return the result."""
    try:
        with Path(file_name).open() as f:
            data = hcl2.load(f)
        return data
    except FileNotFoundError as e:
        print("File not found: ", e)
        return {}