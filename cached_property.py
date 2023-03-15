"""Python Backports"""
# standard library
from collections.abc import Callable
from functools import cached_property as functool_cached_property
from typing import Generic, TypeVar

R = TypeVar('R')


class cached_property(functool_cached_property, Generic[R]):
    """Customized cached_property."""

    # pylint: disable=useless-super-delegation
    def __init__(self, func: Callable[..., R]) -> None:
        """Initialize Class properties."""
        super().__init__(func)

    instances = []

    def __get__(self, instance, owner=None) -> R:
        """Override method."""
        self.instances.append(instance)
        return super().__get__(instance, owner)  # type: ignore

    @staticmethod
    def _reset():
        """Reset cache"""
        for i in cached_property.instances:
            for key, value in i.__dict__.items():
                if isinstance(value, cached_property):
                    del i.__dict__[key]
