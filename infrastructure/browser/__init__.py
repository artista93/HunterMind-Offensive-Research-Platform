# infrastructure/browser/__init__.py

"""
Browser Module - إدارة المتصفحات والتخفي
"""

from .browser_pool import BrowserPool, BrowserInstance, BrowserType, BrowserStatus, get_browser_pool, close_browser_pool
from .stealth_browser import StealthBrowser, get_stealth_browser, BrowserFingerprint
from .playwright_driver import PlaywrightDriver, create_driver
from .chromium_controller import ChromiumController, get_chromium_controller
from .browser_instrumentation import BrowserInstrumentation, create_instrumentation, InstrumentationEvent, InstrumentationData

__all__ = [
    'BrowserPool',
    'BrowserInstance',
    'BrowserType',
    'BrowserStatus',
    'get_browser_pool',
    'close_browser_pool',
    'StealthBrowser',
    'get_stealth_browser',
    'BrowserFingerprint',
    'PlaywrightDriver',
    'create_driver',
    'ChromiumController',
    'get_chromium_controller',
    'BrowserInstrumentation',
    'create_instrumentation',
    'InstrumentationEvent',
    'InstrumentationData',
]
