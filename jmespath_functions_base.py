"""Base class providing shared private helpers for ThreatConnect JMESPath custom functions."""

from typing import Any

from jmespath.visitor import _Expression


class JmespathFunctionsBase:
    """Shared base class for all JMESPath function mixins.

    Provides private helper methods used by the mixin subclasses.
    """

    def _get_expression_key(self, expref: _Expression):
        """Return the key from the expression."""
        match expref.expression['type']:  # type: ignore
            case 'field':
                return expref.expression['value']  # type: ignore

            case 'subexpression':
                return expref.expression.get('children')[-1]['value']  # type: ignore

            case _:
                ex_msg = f'Invalid expression type of {expref.expression["type"]}.'  # type: ignore

                raise RuntimeError(ex_msg)

    def _update_expression_parent(self, expref: _Expression, key: str, item: dict, value: Any):
        """Return the key from the expression."""
        match expref.expression['type']:  # type: ignore
            case 'field':
                item[key] = value

            case 'subexpression':
                expand_item = item
                children = expref.expression.get('children') or []  # type: ignore

                for index, child in enumerate(children):
                    child_value = child['value']
                    expand_item = expand_item[child_value]

                    if index == len(children) - 2:
                        expand_item[key] = value
