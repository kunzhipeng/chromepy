# coding: utf-8

from __future__ import unicode_literals


class CDPException(Exception):
    pass


class UserAbortException(CDPException):
    pass


class TabConnectionException(CDPException):
    pass


class CallMethodException(CDPException):
    pass


class TimeoutException(CDPException):
    pass


class RuntimeException(CDPException):
    pass
