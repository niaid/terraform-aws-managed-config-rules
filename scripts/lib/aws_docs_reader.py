import json

from pathlib import Path
from typing import List

import requests

from bs4 import BeautifulSoup, PageElement

class AwsDocsReader:
    """Parses AWS documentation for a complete list of AWS Config Rules.
    
    Usage:
        >>> reader = AwsDocsReader(
                root_url='https://aws-docs-page',
                managed_rules_page='all-config-rules.html')
            rules = reader.parse_docs()

    The output from the 'parse_docs' method can either be used as input for
    generating HCL code or it can be written directly to file.
    """
    def __init__(self, root_url: str, managed_rules_page: str) -> None:
        self._root_url: str = root_url
        """The root URL for AWS documentation."""
        self._managed_rules_page: str = managed_rules_page
        """The HTML page with the list of AWS-managed Config rules."""

    def clean_string_with_tags(self, value: str) -> str:
        """Remove leading and trailing single quotes and fix code blocks in strings."""
        return value.replace("''", '`',).strip("'")

    def get_page_soup(self, content: str) -> BeautifulSoup:
        """Parse the content of an HTML page and return beautiful soup."""
        return BeautifulSoup(content, 'html.parser')
    
    def get_page_content(self, url: str) -> str:
        """Return the content of an HTML page."""
        return requests.get(url=url).content
    
    def get_config_rules_list(self, soup: BeautifulSoup) -> List[str]:
        """Return a list of all AWS-managed Config rules."""
        topics_header = soup.find('h6', string='Topics').next_sibling
        topics = topics_header.find_all_next('li')
        return [x.string for x in topics]
    
    def get_main_column_content(self, soup: BeautifulSoup) -> BeautifulSoup:
        """Return the main column element with all of the rule descriptions."""
        return soup.find('div', id='main-col-body')
    
    def format_variable_name(self, name: str) -> str:
        """Format the rule name as the name of the parameters variable in Terraform."""
        return name.lower().replace('-', '_') + '_parameters'
    
    def get_rule_description(self, soup: BeautifulSoup) -> str:
        """Parse the content column and return the rule's description."""
        description_tag = soup.find_next('p')
        rule_description = description_tag.string
        if rule_description is None:
            return self.clean_string_with_tags(
                ''.join([repr(x) for x in description_tag.stripped_strings]).replace('\\n', '').replace('\\t', ''))
        return rule_description.strip("'")
    
    def parse_parameter_type(self, page_element: PageElement) -> str:
        """Extract the parameter type from a string."""
        return page_element.string.split(' ')[-1]
    
    def parse_parameter_name(self, page_element: PageElement) -> str:
        """Extract the parameter name from a string."""
        return page_element.string.split(' ')[0]
    
    def parse_parameter_default_value(self, page_element: PageElement) -> str:
        """Extract the parameter default value from a string."""
        return str(page_element.string).split('Default:')[-1].replace('(Optional)', '').strip()
    
    def parse_parameter_description(self, page_element: PageElement) -> str:
        """Extract the parameter description from a string."""
        description_p = page_element.p
        description = description_p.string
        if description is None:
            description = self.clean_string_with_tags(
                ''.join([repr(x) for x in description_p.stripped_strings]))
        return description
    
    def get_rule_identifier(self, soup: BeautifulSoup) -> List[str]:
        """Return the AWS rule identifier."""
        resources_element = soup.find('b', string='Identifier:')
        return resources_element.next_sibling.strip()
    
    def get_rule_parameters(self, soup: BeautifulSoup) -> List[dict]:
        """Parse the rule's parameter list. Returns an empty list if there are no parameters."""
        default = []
        variables_list_element = soup.find('div', class_='variablelist')
        if variables_list_element:
            parameters = []
            contents = variables_list_element.find('dl')
            children = contents.children
            current_parameter = dict()
            for child in children:
                # Return the default value if there are no parameters.
                if child.string == 'None':
                    return default
                # Skip newlines in page elements.
                if child.string == '\n':
                    continue
                # Set the parameter's type.
                if child.name == 'dt' and 'Type:' in child.string:
                    current_parameter['type'] = self.parse_parameter_type(page_element=child)
                    continue
                # Set the parameter's default value.
                elif child.name == 'dt' and 'Default:' in child.string:
                    current_parameter['default'] = self.parse_parameter_default_value(page_element=child)
                    continue
                # Set the parameter's name.
                elif child.name == 'dt' and not current_parameter:
                    current_parameter['name'] = self.parse_parameter_name(page_element=child)
                    # Determine if the parameter is required.
                    if str(child.string).strip().endswith('(Optional)'):
                        current_parameter['optional'] = True
                    else:
                        current_parameter['optional'] = False
                    continue
                # Set the parameter's description. If we've made it this far in the
                # list then the next element is either the start ofanother parameter
                # or it's the last parameter in the list, so we reset the
                # current_parameter value.
                elif child.name == 'dd':
                    current_parameter['description'] = self.parse_parameter_description(page_element=child)
                    parameters.append(current_parameter)
                    current_parameter = dict()
                    continue
            return parameters
        return default
    
    def get_resource_types(self, soup: BeautifulSoup) -> List[str]:
        """Return a list of AWS resource types checked by the rule."""
        default = []
        resources_element = soup.find('b', string='Resource Types:')
        if resources_element:
            return [x.strip() for x in resources_element.next_sibling.split(',')]
        return default
    
    def parse_docs(self) -> list:
        """Parse AWS documentation and extract a complete list of AWS-managed
        Config Rules.
        
        The method logic is kept in a try/except/finally block so that users
        can exit early and still return an incomplete list of rules."""
        soup = self.get_page_soup(self.get_page_content(url=self._managed_rules_page))
        aws_managed_rules = self.get_config_rules_list(soup=soup)

        result = []
        try:
            for rule_name in aws_managed_rules:
                print(f"Parsing {rule_name}")
                rule_soup = self.get_page_soup(
                    content=self.get_page_content(url=self._root_url + rule_name))
                main_column = self.get_main_column_content(soup=rule_soup)
                rule = {'name': rule_name}
                rule['identifier'] = self.get_rule_identifier(soup=main_column)
                rule['variable_name'] = self.format_variable_name(name=rule['identifier'])
                rule['description'] = self.get_rule_description(soup=main_column)
                rule['parameters'] = self.get_rule_parameters(soup=main_column)
                rule['resource_types'] = self.get_resource_types(soup=main_column)
                result.append(rule)
        except Exception as e:
            print(e)
        finally:
            return result


def generate_config_rule_data(root_url: str, managed_rules_page: str) -> None:
    print("Scraping AWS documentation for AWS-managed Config Rules.")
    output_file = 'config_rule_data.json'
    reader = AwsDocsReader(
        root_url=root_url,
        managed_rules_page=managed_rules_page)
    result = reader.parse_docs()

    print(f"Writing result to {output_file}.")
    with Path(output_file).open('w') as f:
        f.write(json.dumps(result, indent=2))
