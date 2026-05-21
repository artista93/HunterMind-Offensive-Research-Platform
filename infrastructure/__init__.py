"""
Infrastructure Module - طبقة البنية التحتية
"""

from . import browser
from . import networking
from . import auth
from . import runtime
from . import sandbox

# استيراد من browser
from .browser import (
    BrowserPool, BrowserInstance, BrowserType, BrowserStatus,
    get_browser_pool, close_browser_pool,
    StealthBrowser, get_stealth_browser,
    PlaywrightDriver, create_driver,
    ChromiumController, get_chromium_controller,
    BrowserInstrumentation, create_instrumentation,
)

# استيراد من networking
from .networking import (
    NetworkMonitor, get_network_monitor,
    ProxyManager, create_proxy_manager,
    RateController, create_rate_controller,
    RequestRouter, create_request_router,
    SessionManager, get_session_manager,
    SessionPool, get_session_pool, close_session_pool,
    TrafficAnalyzer, get_traffic_analyzer,
)

# استيراد من auth
from .auth import (
    AuthManager, AuthType, AuthStatus, AuthCredentials,
    AuthSession, LoginFormDetector, BrowserFingerprint, get_auth_manager,
)

# استيراد من runtime
from .runtime import (
    AsyncRuntime, get_async_runtime,
    CleanupManager, get_cleanup_manager,
    CrashRecovery, get_crash_recovery,
    DependencyContainer, get_dependency_container, inject,
    LifecycleManager, get_lifecycle_manager,
    ProcessManager, get_process_manager,
    ResourceManager, get_resource_manager,
    ResourceMonitor, get_resource_monitor,
    ServiceRegistry, get_service_registry,
    StartupManager, get_startup_manager, run_platform,
)

# استيراد من sandbox
from .sandbox import (
    DockerRuntime, get_docker_runtime, close_docker_runtime,
    IsolatedExecutor, get_isolated_executor,
    TargetEmulator, get_target_emulator,
    LabEnvironment, get_lab_environment,
)

__all__ = [
    'browser',
    'networking',
    'auth',
    'runtime',
    'sandbox',
    # browser
    'BrowserPool', 'BrowserInstance', 'BrowserType', 'BrowserStatus',
    'get_browser_pool', 'close_browser_pool',
    'StealthBrowser', 'get_stealth_browser',
    'PlaywrightDriver', 'create_driver',
    'ChromiumController', 'get_chromium_controller',
    'BrowserInstrumentation', 'create_instrumentation',
    # networking
    'NetworkMonitor', 'get_network_monitor',
    'ProxyManager', 'create_proxy_manager',
    'RateController', 'create_rate_controller',
    'RequestRouter', 'create_request_router',
    'SessionManager', 'get_session_manager',
    'SessionPool', 'get_session_pool', 'close_session_pool',
    'TrafficAnalyzer', 'get_traffic_analyzer',
    # auth
    'AuthManager', 'AuthType', 'AuthStatus', 'AuthCredentials',
    'AuthSession', 'LoginFormDetector', 'BrowserFingerprint', 'get_auth_manager',
    # runtime
    'AsyncRuntime', 'get_async_runtime',
    'CleanupManager', 'get_cleanup_manager',
    'CrashRecovery', 'get_crash_recovery',
    'DependencyContainer', 'get_dependency_container', 'inject',
    'LifecycleManager', 'get_lifecycle_manager',
    'ProcessManager', 'get_process_manager',
    'ResourceManager', 'get_resource_manager',
    'ResourceMonitor', 'get_resource_monitor',
    'ServiceRegistry', 'get_service_registry',
    'StartupManager', 'get_startup_manager', 'run_platform',
    # sandbox
    'DockerRuntime', 'get_docker_runtime', 'close_docker_runtime',
    'IsolatedExecutor', 'get_isolated_executor',
    'TargetEmulator', 'get_target_emulator',
    'LabEnvironment', 'get_lab_environment',
]
