# infrastructure/runtime/__init__.py

"""
Runtime Module - إدارة التشغيل والعمليات
"""

from .async_runtime import AsyncRuntime, AsyncTask, TaskPriority, TaskStatus, get_async_runtime
from .cleanup import CleanupManager, CleanupTarget, CleanupStrategy, CleanupRule, CleanupReport, get_cleanup_manager
from .crash_recovery import CrashRecovery, ComponentState, RecoveryPoint, CrashReport, RecoveryStatus, ComponentType, get_crash_recovery
from .dependency_container import DependencyContainer, Scope, RegistrationType, get_dependency_container, inject
from .lifecycle_manager import LifecycleManager, Component, ComponentState as LCComponentState, ComponentPriority, get_lifecycle_manager, run_platform as lc_run_platform
from .process_manager import ProcessManager, ProcessConfig, ProcessInstance, ProcessStatus, ProcessHealth, get_process_manager
from .resource_manager import ResourceManager, ResourceQuota, ResourceLimit, ResourceType, ResourceUnit, ResourceAlert, get_resource_manager
from .resource_monitor import ResourceMonitor, MetricType, AggregationWindow, MetricDataPoint, AggregatedMetric, ResourceThreshold, get_resource_monitor
from .service_registry import ServiceRegistry, ServiceInstance, ServiceEndpoint, ServiceStatus, ServiceHealth, ServiceRegistration, get_service_registry
from .startup_manager import StartupManager, StartupComponent, StartupPhase, StartupStep, ShutdownPriority, get_startup_manager, run_platform

__all__ = [
    'AsyncRuntime',
    'AsyncTask',
    'TaskPriority',
    'TaskStatus',
    'get_async_runtime',
    'CleanupManager',
    'CleanupTarget',
    'CleanupStrategy',
    'CleanupRule',
    'CleanupReport',
    'get_cleanup_manager',
    'CrashRecovery',
    'ComponentState',
    'RecoveryPoint',
    'CrashReport',
    'RecoveryStatus',
    'ComponentType',
    'get_crash_recovery',
    'DependencyContainer',
    'Scope',
    'RegistrationType',
    'get_dependency_container',
    'inject',
    'LifecycleManager',
    'Component',
    'LCComponentState',
    'ComponentPriority',
    'get_lifecycle_manager',
    'lc_run_platform',
    'ProcessManager',
    'ProcessConfig',
    'ProcessInstance',
    'ProcessStatus',
    'ProcessHealth',
    'get_process_manager',
    'ResourceManager',
    'ResourceQuota',
    'ResourceLimit',
    'ResourceType',
    'ResourceUnit',
    'ResourceAlert',
    'get_resource_manager',
    'ResourceMonitor',
    'MetricType',
    'AggregationWindow',
    'MetricDataPoint',
    'AggregatedMetric',
    'ResourceThreshold',
    'get_resource_monitor',
    'ServiceRegistry',
    'ServiceInstance',
    'ServiceEndpoint',
    'ServiceStatus',
    'ServiceHealth',
    'ServiceRegistration',
    'get_service_registry',
    'StartupManager',
    'StartupComponent',
    'StartupPhase',
    'StartupStep',
    'ShutdownPriority',
    'get_startup_manager',
    'run_platform',
]
