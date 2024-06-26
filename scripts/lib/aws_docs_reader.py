import json
import logging
import re

from pathlib import Path
from typing import List, Optional, Union

import requests

from bs4 import BeautifulSoup, PageElement, ResultSet

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
    
    def get_rule_description(self, soup: BeautifulSoup) -> str:
        """Parse the content column and return the rule's description."""

        '''Some of the rules have warnings or notes about the rule name not
        matching its identifier. We need to skip over these elements and find
        the first <p> tag with the rule description.'''
        for child in soup.contents:
            if child.name == 'p':
                description_tag = child
                break
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
        '''Some of the rules have identifiers that don't match their rule name.
        We need to use the rule name, not the actual identifier, for this
        automation. Warn the user that the two don't match before returning.'''
        identifier_element = soup.find('b', string='Identifier:').next_sibling.strip()
        return identifier_element
    
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
                # list then the next element is either the start of another parameter
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
                logging.info(f"Parsing {rule_name}")
                rule_soup = self.get_page_soup(
                    content=self.get_page_content(url=self._root_url + rule_name))
                main_column = self.get_main_column_content(soup=rule_soup)
                rule = {'name': rule_name}
                rule['identifier'] = self.get_rule_identifier(soup=main_column)
                rule['description'] = self.get_rule_description(soup=main_column)
                rule['parameters'] = self.get_rule_parameters(soup=main_column)
                rule['resource_types'] = self.get_resource_types(soup=main_column)
                result.append(rule)
        except Exception as e:
            logging.error(e)
        finally:
            return result


class SecurityHubControl:
    def __init__(self, soup: ResultSet) -> None:
        self.soup: ResultSet = soup
        self.name: str = soup.string
        self.severity: Optional[str] = None
        self.rule: Optional[str] = None
        '''The page element with the control's corresponding AWS Config Rule has
        inconsistent formatting so we need to handle several cases such as:
        
        - "AWS Config Rule: "
        - "AWS Config rule:"
        - "AWS configrule"

        We're running `re.compile` here for efficiency.
        '''
        self.aws_config_rule_pattern: re.Pattern = re.compile(r'[Aa][Ww][Ss]\s?[Cc]onfig\s?[Rr]ule')
        self._no_rule_configured: str = 'NO_CONFIG_RULE_CONFIGURED'

        self.parse(soup=self.soup)

    @property
    def no_rule_configured(self) -> bool:
        return self.rule == self._no_rule_configured

    def parse(self, soup: ResultSet) -> None:
        for sibling in soup.next_siblings:
            if self.severity and self.rule:
                return
            self.parse_sibling(sibling=sibling)
    
    def parse_sibling(self, sibling):
        if not sibling.name == 'p':
            return

        for child in sibling.children:
            # Check for severity.
            severity = self.find_severity(tag=child)
            if severity is not None and self.severity is None:
                self.severity = severity
                continue
            # Check for rule.
            rule = self.find_rule(child, pattern=self.aws_config_rule_pattern)
            if rule is not None and self.rule is None:
                self.rule = rule
                continue

    def find_severity(self, tag) -> Optional[str]:
        if tag.name == 'b' and "Severity" in tag.string:
            return tag.next_sibling.strip()
        return None
    
    def find_rule(self, tag, pattern) -> Optional[str]:
        if tag.name == 'b' and re.match(pattern, tag.string):
            for child in tag.next_siblings:
                if child.name == 'a' and child.string is not None:
                    return child.string
                if child.name == 'code' and child.string is not None:
                    return child.string
        if tag.string is not None:
            if tag.string.strip().startswith('None'):
                return self._no_rule_configured
            if re.match(pattern, tag.string):
                for child in tag.next_siblings:
                    if child.name == 'a':
                        return child.string
                    if child.name == 'code':
                        return child.string
        return None
    
    def get_aws_config_rule_name(self, tag) -> str:
        if tag.name == 'a':
            return tag.string
        if tag.name == 'code':
            return tag.string
        raise ValueError(f"Could not find AWS Config Rule name in {tag}")
    
    def to_dict(self) -> dict:
        return {
            'severity': self.severity,
            'rule': self.rule,
            'control': self.name}


def generate_config_rule_data(root_url: str, managed_rules_page: str, output_file: Union[Path, str]) -> None:
    logging.info("Scraping AWS documentation for AWS-managed Config Rules.")
    reader = AwsDocsReader(
        root_url=root_url,
        managed_rules_page=managed_rules_page)
    result = reader.parse_docs()

    logging.info(f"Writing result to {output_file}.")
    with Path(output_file).open('w') as f:
        f.write(json.dumps(result, indent=2))

def generate_security_hub_controls_data(
        root_url: str,
        controls_ref_page: str,
        output_file: Union[Path, str]) -> None:
    controls = parse_security_hub_docs(
        controls_userguide_root=root_url, controls_ref_page=controls_ref_page)
    with Path(output_file).open('w') as f:
        f.write(json.dumps(controls, indent=2))

def parse_security_hub_docs(controls_userguide_root: str, controls_ref_page: str):
    control_references_url = f"{controls_userguide_root}/{controls_ref_page}"
    soup = get_page_soup(get_page_content(url=control_references_url))
    all_controls = get_security_hub_controls(soup=soup)
    result = []

    for pages in all_controls:
        page = pages[1].strip('.')
        page_soup = get_page_soup(
            content=get_page_content(url=f"{controls_userguide_root}{page}"))
        page_controls_soup = page_soup.find_all('h2')
        logging.info(f"Working on controls: {page}")
        counter = 1
        controls_length = len(page_controls_soup)
        for control in page_controls_soup:
            logging.info(f"Parsing ({counter}/{controls_length})")
            security_hub_control = SecurityHubControl(soup=control)
            if security_hub_control.no_rule_configured:
                logging.warning(f"Control {control.string} has no AWS Config Rule configured. Skipping")
                counter += 1
                continue
            if not security_hub_control.severity or not security_hub_control.rule:
                logging.error(f"Failed to parse control {control.string}")
                counter += 1
                continue
            result.append(security_hub_control.to_dict())
            counter += 1
    return result

def get_page_soup(content: str) -> BeautifulSoup:
    """Parse the content of an HTML page and return beautiful soup."""
    return BeautifulSoup(content, 'html.parser')

def get_page_content(url: str) -> str:
    """Return the content of an HTML page."""
    return requests.get(url=url).content

def get_security_hub_controls(soup: BeautifulSoup) -> List[str]:
    """Return a list of all AWS Security Hub controls."""
    topics_header = soup.find('h6', string='Topics').next_sibling
    topics = topics_header.find_all_next('li')
    return [(x.string, x.find_next('a').attrs['href']) for x in topics]
