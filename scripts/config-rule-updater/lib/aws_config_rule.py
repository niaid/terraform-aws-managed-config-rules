import json
import re
import yaml

from typing import Union, List


class AwsConfigRuleLocal:
    def __init__(self, name: str, data: dict) -> None:
        self.name = name
        self.severity = data['severity']


class AwsConfigRule:
    def __init__(self, data: dict) -> None:
        self.name: str = data['name']
        """The name of the rule."""
        self.tf_variable_name: str = data['variable_name']
        """The name of the Terraform variable for the rule's parameters."""
        self.tf_variable_description: str = data['description']
        """The Terraform parameters variable description."""
        self.parameters_data: List[str] = data['parameters']
        """A list of the rule's parameters."""
        self.resource_types: List[str] = data.get('resource_types', [])
        """A list of resource types checked by the rule."""
        self._rule_severity: str = data.get('severity', 'Medium')
        """The level of severity of noncompliant resources."""

    @property
    def rule_severity(self) -> str:
        """The level of severity of noncompliant resources."""
        return self._rule_severity

    def _format_parameter_name(self, param_name: str) -> str:
        """Return the parameter name with the first letter lowercased."""
        return param_name[0].lower() + param_name[1:]
    
    def _map_param_type(self, param_type: str) -> str:
        """Map the different value types to types expected by Terraform."""
        return {
            'int': 'number',
            'String': 'string',
            'CSV': 'string',
            'string': 'string',
            'StringMap': 'string',
            'double': 'number',
            'boolean': 'bool'
        }[param_type]
    
    def _get_default_param_value(self, value, value_type) -> Union[str, int, bool]:
        """Cast the value to a type corresponding to the provided 'value_type'.
        
        Strings are returned with escaped quotes."""
        if value_type == 'string':
            return f"\"{value}\""
        elif value_type == 'number':
            return int(value)
        if value_type == 'bool':
            return value
        
    def set_severity_level(self, value: str) -> None:
        """Set the rule's severity level."""
        self._rule_severity = value
        
    def cleanup_description_string(self, input_str: str) -> str:
        """Fix single/double quotes and tick marks so that the description
        is compatible with HCL variable descriptions."""
        result = ""
        for index, character in enumerate(input_str):
            if character in ["'", "\u2018", "\u2019"]: # ASCII and Unicode single quotes
                """Check for possessive ('s) characters and keep those. Otherwise, replace
                them with empty spaces."""
                result += self.replace_single_quotes(input_str[index:index + 3])
            elif character in ['"', "`"]: # We want to remove these entirely.
                result += ' '
            else:
                result += character
        return result.strip()

    def locals_description(self, max_length: str=256) -> str:
        """The description for each rule in the locals block cannot be longer
        than {max_length} characters. This method truncates the description to
        end on the last full word at the limit followed by an ellipsis."""
        # Remove newlines, strip trailing quotes, replace internal quotes, and join the strings.
        full_description = ' '.join(
            [self.cleanup_description_string(x) for x in self.tf_variable_description.split('\n')])
        full_description = self.replace_multiple_whitespace_with_single(full_description)
        # Return the full description if it's already shorter than the limit.
        if len(full_description) <= max_length:
            return full_description
        
        # Truncate the description and determine if we need to shorten it
        # further to support the trailing ellipsis or return it as is.
        short_description = full_description[:max_length]
        # If it ends in a period then that's probably the end of a sentence.
        if short_description[-1] == '.':
            return short_description
        
        # Find the last whitespace character in the string (indicating the end
        # of a complete word) and replace it with an ellipsis '...'.
        result = self.replace_last_whitespace_char_with_ellipsis(short_description)
        while True:
            if len(result) <= max_length:
                break
            result = self.replace_last_whitespace_char_with_ellipsis(result)

        return result
        
    def replace_multiple_whitespace_with_single(self, input_str: str) -> str:
        """Replace multiple whitespace chars with a single whitespace character."""
        # Matches any sequence of consecutive whitespace characters.
        pattern = re.compile(r'\s+')

        # Replace multiple whitespaces with a single whitespace.
        return pattern.sub(' ', input_str)
    
    def replace_single_quotes(self, input_str: str) -> str:
        """Returns either a single quote or a space depending on whether the
        string argument represents a possessive apostrophe."""
        if input_str.endswith("s ") or input_str.endswith("s."):
            return "'"
        return ' '
    
    def replace_colons_with_equals(self, input_str: str) -> str:
        """Replace colons with ' = ' to be compatible with HCL structure."""
        # Matches any colon not between quotes.
        pattern = re.compile(r'("[^"]*")|(:)')

        # Replace colons with equals except for those between quotes.
        return pattern.sub(lambda m: m.group(1) or " = ", input_str)
    
    def replace_last_whitespace_char_with_ellipsis(self, input_str: str) -> str:
        """Replace the last whitespace character with '...'."""
        # Find the last whitespace character.
        last_space = input_str.rfind(' ')

        # Return the modified string if the whitespace char isn't the last char.
        if last_space != -1:
            return input_str[:last_space] + '...'
        else:
            return input_str

    def tf_variable_type(self) -> str:
        """Return the type of the variable.
        
        All returned types are of type 'object()'. Parameter attributes are either
        given a type like 'string' or 'number', or they are given an 'optional()'
        type if the value is not required.
        
        Example:
            object({
                masterAccountId = optional(string, null)
            })
            
        Example:
            object({
                maxAccessKeyAge = number
            })
            
        Example:
            object({
                recoveryPointAgeUnit  = string
                recoveryPointAgeValue = number
                resourceId            = optional(string, null)
                resourceTags          = optional(string, null)
            })"""
        result = {}
        for param in self.parameters_data:
            param_name = self._format_parameter_name(param['name'])
            param_type = self._map_param_type(param['type'])

            # Set the parameter as optional if no default value is found.
            if param.get('default', None):
                result[param_name] = f"optional({param_type}, {self._get_default_param_value(param['default'], param_type)})"
            # elif param.get('optional', False):
            #     result[param_name] = f"optional({param_type}, null)"
            else:
                result[param_name] = f"optional({param_type}, null)"
        return f"object({{\n{yaml.dump(result, default_flow_style=False)}}})"
    
    def tf_variable_default_value(self) -> str:
        result = {}
        for param in self.parameters_data:
            # Skip this parameter if it doesn't have a default value.
            if param.get('default', None) is None:
                continue

            param_name = self._format_parameter_name(param['name'])
            param_value = self._get_default_param_value(
                value=param['default'],
                value_type=self._map_param_type(param['type']))
            result[param_name] = param_value
        if result:
            # In order for the HCL to be generated correctly, we first need to
            # generate the object definition in YAML format. Then we replace the
            # colon characters between the key/value pairs and ignore the
            # colons within the default string values themselves.
            raw_string = yaml.dump(result, default_flow_style=False, default_style='')
            fixed = self.replace_colons_with_equals(raw_string)
            return f"{{\n{fixed}}}"
        return None