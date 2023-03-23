"""Declares a scoped_property decorator"""

# standard library
import os
import threading
from collections.abc import Callable
from typing import Any, Generic, TypeVar

T = TypeVar('T')


class scoped_property(Generic[T]):
    """Makes a value unique for each thread and also acts as a @property decorator.

    Essentially, a thread-and-process local value.  When used to decorate a function, will
    treat that function as a factory for the underlying value, and will invoke it to produce a value
    for each thread the value is requested from.

    Note that this also provides a cache: each thread will re-use the value previously created
    for it.
    """

    instances = []

    def __init__(self, wrapped: Callable[..., T]):
        """Initialize."""

        scoped_property.instances.append(self)
        self.wrapped = wrapped
        self.value = threading.local()

    def __del__(self):
        """Remove instance from the instances class variable when it's destroyed."""
        scoped_property.instances = [i for i in scoped_property.instances if i != self]

    def __get__(self, instance: Any, _: Any) -> T:
        """Return a thread-and-process-local value.

        Implementation per the descriptor protocol.

        Args:
            instance: the instance this property is being resolved for.
            owner: same as instance.
        """
        if hasattr(self.value, 'data'):
            # A value has been created for this thread already, but we have to make sure we're in
            # the same process (threads are duplicated when a process is forked).
            pid, value = self.value.data
            if pid != os.getpid():
                return self._create_value(self.wrapped, instance)

            return value

        # A value has *not* been created for the calling thread
        # yet, so use the factory to create a new one.
        new_value = self._create_value(self.wrapped, instance)
        return new_value

    def _create_value(self, wrapped, *args, **kwargs) -> T:
        """Call the wrapped factory function to get a new value."""
        data = wrapped(*args, **kwargs)
        setattr(self.value, 'data', (os.getpid(), data))
        return data

    @staticmethod
    def _reset():
        for i in scoped_property.instances:
            i.value = threading.local()