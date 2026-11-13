import typing
from dataclasses import fields, is_dataclass
from functools import lru_cache
from typing import Callable, Dict, Iterable, Optional, Tuple


def validate_types(value: object) -> None:
    """Raise TypeError unless value, and everything it contains, has the type its dataclass fields declare.

    The converters build the domain objects straight from JSON, where any field can hold anything. Checking
    the result once keeps a malformed answer from failing later, somewhere in a service or a table.
    """
    if not _checker(type(value))(value):
        _explain(value)  # the slow way, to say where
        raise TypeError('response does not have the expected types')


_checkers: Dict[object, Callable[[object], bool]] = {}


def _checker(expected: object) -> Callable[[object], bool]:
    """Build the test for one declared type once; a response has the same few types thousands of times."""
    if expected not in _checkers:
        _checkers[expected] = _build_checker(getattr(expected, '__supertype__', expected))  # NewType
    return _checkers[expected]


def _build_checker(expected: object) -> Callable[[object], bool]:
    origin, arguments = typing.get_origin(expected), typing.get_args(expected)
    if origin is typing.Union:
        optional = type(None) in arguments
        checks = [_checker(argument) for argument in arguments if argument is not type(None)]
        return lambda value: optional if value is None else all(check(value) for check in checks)
    if origin in (list, tuple):
        item = _checker(arguments[0])
        return lambda value: isinstance(value, origin) and all(map(item, value))
    if isinstance(expected, type):
        return _build_class_checker(expected)
    return lambda value: True


def _build_class_checker(expected: type) -> Callable[[object], bool]:
    if is_dataclass(expected):
        field_checks = [(name, _checker(hint)) for name, hint in _field_types(expected)]
        return lambda value: isinstance(value, expected) and all(
            check(getattr(value, name)) for name, check in field_checks)
    if issubclass(expected, (list, tuple)):
        return lambda value: isinstance(value, expected) and all(_checker(type(item))(item) for item in value)
    if expected is float:
        return lambda value: type(value) in (float, int)  # JSON has one number type
    if expected is int:
        return lambda value: isinstance(value, int) and type(value) is not bool
    return lambda value: isinstance(value, expected)


def _explain(value: object, expected: Optional[object] = None, where: str = 'response') -> None:
    """Raise TypeError naming the first value that does not have its declared type."""
    expected = type(value) if expected is None else getattr(expected, '__supertype__', expected)  # NewType
    origin, arguments = typing.get_origin(expected), typing.get_args(expected)
    if origin is typing.Union:
        if value is not None or type(None) not in arguments:
            for candidate in (argument for argument in arguments if argument is not type(None)):
                _explain(value, candidate, where)
    elif origin in (list, tuple):
        if not isinstance(value, origin):
            raise TypeError(f'{where} is not a {origin.__name__}')
        _validate_items(value, arguments[0], where)
    elif isinstance(expected, type):
        _validate_instance(value, expected, where)


def _validate_instance(value: object, expected: type, where: str) -> None:
    if expected is float and type(value) is int:  # JSON has one number type
        return
    # bool is an int in Python, but never what an integer field of the API means
    if not isinstance(value, expected) or (type(value) is bool and expected is not bool):
        raise TypeError(f'{where} is not of type {expected.__name__}')
    if isinstance(value, (list, tuple)):
        _validate_items(value, None, where)  # undeclared element type: check each item as it is
    elif is_dataclass(expected):
        for name, hint in _field_types(expected):
            _explain(getattr(value, name), hint, f'{where}.{name}')


@lru_cache(maxsize=None)
def _field_types(dataclass_type: type) -> Tuple[Tuple[str, object], ...]:
    hints = typing.get_type_hints(dataclass_type)
    return tuple((field.name, hints[field.name]) for field in fields(dataclass_type))


def _validate_items(items: Iterable[object], expected: Optional[object], where: str) -> None:
    for index, item in enumerate(items):
        _explain(item, expected, f'{where}[{index}]')
