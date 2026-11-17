"""Small helpers that reproduce the Go behaviour the upstream bridge relies on:
``time.Time`` values and ``fmt.Sprint`` formatting of host values."""
from __future__ import annotations

import calendar
import math
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GoTime:
    """A UTC instant with nanosecond precision (Go's time.Time in UTC)."""

    seconds: int
    nanos: int = 0

    @classmethod
    def now(cls) -> "GoTime":
        ns = time.time_ns()
        return cls(ns // 1_000_000_000, ns % 1_000_000_000)

    @classmethod
    def from_float(cls, value: float) -> "GoTime":
        """time.Unix(int64(whole), int64(fraction*1e9)) after math.Modf."""
        fraction, whole = math.modf(value)
        seconds = int(whole)
        nanos = int(fraction * 1e9)
        seconds += nanos // 1_000_000_000
        return cls(seconds, nanos % 1_000_000_000)

    @classmethod
    def date(cls, year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> "GoTime":
        """time.Date in UTC, normalizing out-of-range fields like Go."""
        months = (year * 12 + (month - 1))
        year, month = divmod(months, 12)
        days = _days_from_civil(year, month + 1, 1) + (day - 1)
        return cls(days * 86400 + hour * 3600 + minute * 60 + second, 0)

    def unix_float(self) -> float:
        return float(self.seconds) + float(self.nanos) / 1e9

    def compare(self, other: "GoTime") -> int:
        a, b = (self.seconds, self.nanos), (other.seconds, other.nanos)
        return (a > b) - (a < b)

    def sub_seconds(self, other: "GoTime") -> float:
        """t.Sub(u).Seconds()"""
        return float((self.seconds - other.seconds) * 1_000_000_000 + (self.nanos - other.nanos)) / 1e9

    def fields(self):
        """(second, minute, hour, day, month-1, year-1900, weekday, yearday-1)"""
        days, remainder = divmod(self.seconds, 86400)
        year, month, day = _civil_from_days(days)
        hour, remainder = divmod(remainder, 3600)
        minute, second = divmod(remainder, 60)
        weekday = (days + 4) % 7  # 1970-01-01 was a Thursday
        yearday = days - _days_from_civil(year, 1, 1)
        return second, minute, hour, day, month - 1, year - 1900, weekday, yearday

    def http_date(self) -> str:
        second, minute, hour, day, month, year, weekday, _ = self.fields()
        return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (
            _WEEKDAYS[weekday], day, _MONTHS[month], year + 1900, hour, minute, second)

    def go_string(self) -> str:
        second, minute, hour, day, month, year, _, _ = self.fields()
        text = "%04d-%02d-%02d %02d:%02d:%02d" % (year + 1900, month + 1, day, hour, minute, second)
        if self.nanos:
            text += ("." + "%09d" % self.nanos).rstrip("0")
        return text + " +0000 UTC"


_WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _days_from_civil(year: int, month: int, day: int) -> int:
    year -= month <= 2
    era = (year if year >= 0 else year - 399) // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(days: int):
    days += 719468
    era = (days if days >= 0 else days - 146096) // 146097
    doe = days - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    year = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + (3 if mp < 10 else -9)
    return year + (month <= 2), month, day


def parse_http_date(value: str) -> GoTime:
    """time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", value)"""
    parsed = time.strptime(value, "%a, %d %b %Y %H:%M:%S GMT")
    return GoTime(calendar.timegm(parsed), 0)


def go_float(value: float) -> str:
    """fmt's %v for a float64 (strconv 'g', shortest): the shortest
    round-tripping digits, with an exponent when the decimal exponent is
    below -4 or at least 6."""
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value == 0:
        return "-0" if math.copysign(1.0, value) < 0 else "0"
    from decimal import Decimal

    sign, digits, exponent = Decimal(repr(float(value))).as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    text = "".join(str(d) for d in digits)
    point = len(digits) + exponent  # digits before the decimal point
    prefix = "-" if sign else ""
    x = point - 1
    if x < -4 or x >= 6:
        mantissa = text[0] + ("." + text[1:] if len(text) > 1 else "")
        return f"{prefix}{mantissa}e{'-' if x < 0 else '+'}{abs(x):02d}"
    if point <= 0:
        return prefix + "0." + "0" * (-point) + text
    if point >= len(text):
        return prefix + text + "0" * (point - len(text))
    return prefix + text[:point] + "." + text[point:]


def go_sprint(value: Any) -> str:
    """fmt.Sprint of a host value."""
    if value is None:
        return "<nil>"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return go_float(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return "[" + " ".join(str(b) for b in value) + "]"
    if isinstance(value, GoTime):
        return value.go_string()
    if isinstance(value, dict):
        return "map[" + " ".join(f"{k}:{go_sprint(v)}" for k, v in sorted(value.items())) + "]"
    if isinstance(value, (list, tuple)):
        return "[" + " ".join(go_sprint(item) for item in value) + "]"
    return str(value)
