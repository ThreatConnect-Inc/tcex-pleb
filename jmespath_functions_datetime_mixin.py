"""Datetime functions for ThreatConnect JMESPath custom functions."""

import time
from datetime import UTC, datetime

from jmespath import functions

from ..util import Util
from .jmespath_functions_base import JmespathFunctionsBase


class DateTimeFunctionsMixin(JmespathFunctionsBase):
    """Mixin providing datetime JMESPath functions.

    All parsing is delegated to Util.any_to_datetime(), which accepts ISO 8601 strings,
    epoch milliseconds, epoch seconds, RFC 3339, natural language expressions, and more.

    Functions: datetime_format, datetime_now, datetime_now_utc, datetime_to_epoch.
    """

    @functions.signature({'types': ['number', 'string']}, {'types': ['string']})
    def _func_datetime_format(self, value: int | str, fmt: str) -> str:
        """Format any datetime expression using a strftime pattern.

        Accepts any parseable datetime value: ISO 8601 strings, epoch milliseconds,
        epoch seconds, RFC 3339, natural language expressions, and more.

        Expression (ISO string):
        datetime_format(ts, '%Y-%m-%dT%H:%M:%SZ')

        Data:
        {"ts": "2024-01-15 08:30:00"}

        Output:
        "2024-01-15T08:30:00Z"

        Expression (epoch milliseconds):
        datetime_format(ts, '%Y-%m-%dT%H:%M:%SZ')

        Data:
        {"ts": 1705307400000}

        Output:
        "2024-01-15T08:30:00Z"

        Expression (date-only output):
        datetime_format(ts, '%Y-%m-%d')

        Data:
        {"ts": "2024-01-15T08:30:00Z"}

        Output:
        "2024-01-15"
        """
        return Util.any_to_datetime(value).strftime(fmt)

    @functions.signature()
    def _func_datetime_now(self) -> int:
        """Return the current UTC time as an epoch millisecond timestamp.

        Expression:
        datetime_now()

        Output:
        1705307400000
        """
        return time.time_ns() // 1_000_000

    @functions.signature()
    def _func_datetime_now_utc(self) -> str:
        """Return the current UTC time as an RFC 3339 string.

        Expression:
        datetime_now_utc()

        Output:
        "2024-01-15T08:30:00Z"
        """
        return datetime.now(tz=UTC).strftime('%Y-%m-%dT%H:%M:%SZ')

    @functions.signature({'types': ['number', 'string']})
    def _func_datetime_to_epoch(self, value: int | str) -> int:
        """Convert any datetime expression to an epoch millisecond timestamp.

        Accepts any parseable datetime value: ISO 8601 strings, epoch milliseconds,
        epoch seconds, RFC 3339, and more.

        Expression (ISO string):
        datetime_to_epoch(ts)

        Data:
        {"ts": "2024-01-15T08:30:00Z"}

        Output:
        1705307400000

        Expression (epoch milliseconds round-trip):
        datetime_to_epoch(ts)

        Data:
        {"ts": 1705307400000}

        Output:
        1705307400000
        """
        return int(Util.any_to_datetime(value).timestamp() * 1000)
