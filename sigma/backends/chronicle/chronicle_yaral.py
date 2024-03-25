from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag
from sigma.conversion.deferred import DeferredQueryExpression, DeferredTextQueryExpression
from sigma.types import re, SigmaString, SigmaNumber
import sigma
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.pipelines.chronicle.chronicle import chronicle_pipeline
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND
from typing import Union, ClassVar, Optional, Tuple, List, Dict, Any
from sigma.conditions import (
    ConditionItem,
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
    ConditionType,
)
from sigma.processing.postprocessing import ReplaceQueryTransformation

class chronicleBackendYaral(TextQueryBackend):
    """chronicle YARA-L backend."""
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "chronicle YARA-L backend"
    formats : Dict[str, str] = {
        "default": "YARAL Rules",
        
    }
    # register the output formats


    requires_pipeline : bool = True

    backend_processing_pipeline : ClassVar[chronicle_pipeline] = chronicle_pipeline()

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    parenthesize: bool = True
    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = " = "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    #field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    str_double_quote : ClassVar[str] = '"'
    str_single_quote : ClassVar[str] = "'"
    str_triple_quote : ClassVar[str] = '"""'
    ## Values
    str_quote       : ClassVar[str] = ''     # string quoting character (added as escaping character)
    str_quote_pattern: ClassVar[Pattern] = re.compile(r"^$")
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    startswith_expression : ClassVar[str] = "{field} = /^{value}.*/ nocase"
    endswith_expression   : ClassVar[str] = "{field} = /.*{value}$/ nocase"
    contains_expression   : ClassVar[str] = "{field} = /.*{value}.*/ nocase"
    wildcard_match_expression : ClassVar[str] = "{field} match {value}"

    # String matching operators. if none is appropriate eq_token is used.
    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "re.regex($selection.{field}, `{regex}`) nocase"
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ("`")          # List of strings that are escaped
    re_escape_escape_char : bool = False                # If True, the escape character is also escaped
    re_flag_prefix : bool = False                      # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags : Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE : "m",
        SigmaRegularExpressionFlag.DOTALL    : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.

    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression : ClassVar[Optional[str]] = None  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only).

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    
    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.
    no_case_str_expression: ClassVar[str] = "{value} nocase"
    # Null/None expressions
    field_null_expression : ClassVar[str] = '{field} = "None"'          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    #field_exists_expression : ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    #field_not_exists_expression : ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.l

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = True                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    #or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    #and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    #unbound_value_re_expression : ClassVar[str] = '_=~{value}'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def get_quote_type(self, string_val):
        """Returns the shortest correct quote type (single, double, or trip) based on quote characters contained within an input string"""
        if '"' and "'" in string_val:
            quote = self.str_triple_quote
        elif '"' in string_val:
            quote = self.str_single_quote
        else:
            quote = self.str_double_quote

        return quote

    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        #field = cond.field
        field = '$selection.'+cond.field
        val = cond.value.to_plain()
        val_no_wc = val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi)
        quote = self.get_quote_type(val)
        # contains
        if val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single):
            result = self.contains_expression.format(field=field, value=val_no_wc.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)"))
        # startswith
        elif val.endswith(self.wildcard_single) and not val.startswith(self.wildcard_single):
            result = self.startswith_expression.format(field=field, value=val_no_wc.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)"))
        # endswith
        elif val.startswith(self.wildcard_single) and not val.endswith(self.wildcard_single):
            result = self.endswith_expression.format(field=field, value=val_no_wc.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)"))
        # plain equals
        else:
            no_case_str = self.no_case_str_expression.format(value=quote + self.convert_value_str(cond.value, state) + quote)
            result = field + self.eq_token + no_case_str

        return result


    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        vals = [str(arg.value.to_plain() or "") for arg in cond.args]
        field = '$selection.'+cond.args[0].field
        #field = cond.args[0].field

        # or-in condition
        if isinstance(cond, ConditionOR):
            # contains
            if all(val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single) for val in vals):
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                #escaped_vals = [val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(") for val in vals_no_wc]
                result = ' OR '.join([self.contains_expression.format(field=field, value=val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")) for val in vals_no_wc])
            # starts with
            elif all(val.endswith(self.wildcard_single) and not val.startswith(self.wildcard_single) for val in vals):
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                #escaped_vals = [val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(") for val in vals_no_wc]
                result = ' OR '.join([self.startswith_expression.format(field=field, value=val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")) for val in vals_no_wc])
            # ends with
            elif all(val.startswith(self.wildcard_single) and not val.endswith(self.wildcard_single) for val in vals):
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                #escaped_vals = [val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(") for val in vals_no_wc]
                result = ' OR '.join([self.endswith_expression.format(field=field, value=val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")) for val in vals_no_wc])
            # plain equals can't use list must be array
            else:
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                result = ' OR '.join([f'{field} = "{val.lstrip(self.wildcard_single).rstrip(self.wildcard_single)}"' for val in vals])
        
        elif isinstance(cond, ConditionAND):
            if all(val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single) for val in vals):
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                #escaped_vals = [val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/") for val in vals_no_wc]
                result = ' AND '.join([self.contains_expression.format(field=field, value=val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")) for val in vals_no_wc])
            # starts with
            elif all(val.endswith(self.wildcard_single) and not val.startswith(self.wildcard_single) for val in vals):
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                #escaped_vals = [val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/") for val in vals_no_wc]
                result = ' AND '.join([self.startswith_expression.format(field=field, value=val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")) for val in vals_no_wc])
            # ends with
            elif all(val.startswith(self.wildcard_single) and not val.endswith(self.wildcard_single) for val in vals):
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                #escaped_vals = [val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/") for val in vals_no_wc]
                result = ' AND '.join([self.endswith_expression.format(field=field, value=val.replace("\\", "\\\\").replace("$", "\\$").replace(".", "\\.").replace("/", "\\/").replace("(", "\\(").replace(")", "\\)")) for val in vals_no_wc])
            # plain equals can't use list must be array
            else:
                vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
                result = ' AND '.join([f'{field} = "{val.lstrip(self.wildcard_single).rstrip(self.wildcard_single)}"' for val in vals])
            
        else:
            # ... other conditions ...
            print("pass")
            pass

        return result
    
    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field = number value expressions"""
        result = cond.field + self.eq_token + str(f'"{cond.value}"')
        return result
    
    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        # we replace the field in quarry with an $selection.field
        return f"""rule SIGMA_{(rule.title).replace(" ","_")}\n{{\n    meta:\n        author = "{rule.author}"\n        description = "{rule.description}"\n        id = "{rule.id}"\n        status = "{rule.level}"\n        false_positives = "{rule.falsepositives}"\n        references = "{rule.references}"\n    events:\n        ({query})\n    condition:\n        $selection\n}}"""