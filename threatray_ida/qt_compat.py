"""Qt binding compatibility layer.

IDA <= 9.1 ships PyQt5; IDA >= 9.2 ships PySide6 with a PyQt5 shim that
prompts the user on first import and is incomplete (e.g. ``QShortcut``
is absent from ``QtWidgets`` because Qt6 moved it to ``QtGui``).
Importing through this module picks the native binding for the running
IDA and exposes a stable surface so call sites stay binding-agnostic.
"""
try:
    import idaapi
    _ida_sdk_version = idaapi.IDA_SDK_VERSION
except ImportError:
    _ida_sdk_version = 0  # not running inside IDA (e.g. unit tests) → use PyQt5

if _ida_sdk_version >= 920:
    from PySide6 import QtCore, QtGui, QtWidgets
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QAction, QShortcut
    from PySide6.QtWidgets import QDialog, QDialogButtonBox
    from shiboken6 import wrapInstance as _wrap_instance

    Signal = QtCore.Signal
else:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QAction, QDialog, QDialogButtonBox, QShortcut
    from PyQt5.sip import wrapinstance as _wrap_instance

    Signal = QtCore.pyqtSignal


def wrap_instance(ptr: int, cls):
    return _wrap_instance(int(ptr), cls)


__all__ = [
    "QtCore",
    "QtGui",
    "QtWidgets",
    "Qt",
    "QAction",
    "QDialog",
    "QDialogButtonBox",
    "QShortcut",
    "Signal",
    "wrap_instance",
]
