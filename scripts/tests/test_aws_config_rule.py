import unittest

from lib.aws_config_rule import AwsConfigRule

class TestAwsConfigRule(unittest.TestCase):
    def setUp(self):
        self.rule_variable_name = 'access_keys_rotated_parameters'
        self.rule_description = "Checks if active IAM access keys are rotated (changed) within the number of days specified in`maxAccessKeyAge`. The rule is NON_COMPLIANT if access keys are not rotated within the specified time period. The default value is 90 days."
        self.rule_parameters = [
            {
                'name': 'maxAccessKeyAge',
                'optional': False,
                'type': 'int',
                'default': '90',
                'description': "Maximum number of days without rotation. Default 90."
            }
        ]
        self.rule_resource_types = ['AWS::IAM::User']
        self.rule_identifier = 'ACCESS_KEYS_ROTATED'
        self.data = {
            'variable_name': self.rule_variable_name,
            'description': self.rule_description,
            'parameters': self.rule_parameters,
            'resource_types': self.rule_resource_types,
            'identifier': self.rule_identifier,
        }

    def test_tf_variable_name(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.tf_variable_name, self.rule_variable_name)

    def test_name(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.name, 'access-keys-rotated')

    def test_tf_variable_description(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.tf_variable_description, self.rule_description)

    def test_parameters_data(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.parameters_data, self.rule_parameters)

    def test_resource_types(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.resource_types, self.rule_resource_types)

        # Setup
        self.data.pop('resource_types')
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.resource_types, [])

    def test_rule_severity(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.rule_severity, 'Medium')

        # Setup
        self.data['severity'] = 'Low'
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.rule_severity, 'Low')

    def test__format_parameter_name(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule._format_parameter_name('MaxAccessKeyAge'), 'maxAccessKeyAge')

    def test__map_param_type(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule._map_param_type('int'), 'number')
        self.assertEqual(rule._map_param_type('String'), 'string')
        self.assertEqual(rule._map_param_type('CSV'), 'string')
        self.assertEqual(rule._map_param_type('string'), 'string')
        self.assertEqual(rule._map_param_type('StringMap'), 'string')
        self.assertEqual(rule._map_param_type('double'), 'number')
        self.assertEqual(rule._map_param_type('boolean'), 'bool')

    def test__get_default_param_value(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule._get_default_param_value('90', 'string'), '"90"')
        self.assertEqual(rule._get_default_param_value('90', 'number'), 90)
        self.assertEqual(rule._get_default_param_value(True, 'bool'), True)
        self.assertEqual(rule._get_default_param_value(False, 'bool'), False)

    def test_set_severity_level(self):
        # Setup
        rule = AwsConfigRule(self.data)
        rule.set_severity_level('Low')

        # Assertions
        self.assertEqual(rule.rule_severity, 'Low')

    def test_replace_multiple_whitespace_with_single(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(
            rule.replace_multiple_whitespace_with_single("This   is   a   test"),
            'This is a test')

    def test_replace_single_quotes(self):
        # Setup
        rule = AwsConfigRule(self.data)
        
        # Assertions
        self.assertEqual(rule.replace_single_quotes("Strings "), "'")
        self.assertEqual(rule.replace_single_quotes("Strings."), "'")
        self.assertEqual(rule.replace_single_quotes("String"), ' ')

    def test_replace_colons_with_equals(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.tf_variable_default_value(), "{\nmaxAccessKeyAge =  90\n}")

    def test_replace_last_whitespace_char_with_ellipsis(self):
        # Setup
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.replace_last_whitespace_char_with_ellipsis("This is a test "), "This is a test...")
        self.assertEqual(rule.replace_last_whitespace_char_with_ellipsis("This is a test"), "This is a...")
        self.assertEqual(rule.replace_last_whitespace_char_with_ellipsis(""), "...")
        self.assertEqual(rule.replace_last_whitespace_char_with_ellipsis(" "), "...")

    def test_locals_description(self):
        # Setup
        short_description = 'a' * 256
        long_description = 'a' * 257
        long_description_with_space = f"{'a' * 253} aaa"
        self.data['description'] = short_description
        rule = AwsConfigRule(self.data)

        # Assertions
        self.assertEqual(rule.locals_description(), short_description)

        # Setup
        self.data['description'] = long_description
        rule = AwsConfigRule(self.data)
        self.assertEqual(rule.locals_description(), '...')

        # Setup
        self.data['description'] = long_description_with_space
        rule = AwsConfigRule(self.data)
        self.assertEqual(rule.locals_description(), f"{'a' * 253}...")