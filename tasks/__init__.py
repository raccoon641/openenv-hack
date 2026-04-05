from .sql_injection import SQLInjectionTask
from .auth_bypass   import AuthBypassTask
from .xss_injection import XSSInjectionTask

# Registry: task_id → class
TASK_REGISTRY = {
    SQLInjectionTask.TASK_ID: SQLInjectionTask,
    AuthBypassTask.TASK_ID:   AuthBypassTask,
    XSSInjectionTask.TASK_ID: XSSInjectionTask,
}

__all__ = [
    "TASK_REGISTRY",
    "SQLInjectionTask",
    "AuthBypassTask",
    "XSSInjectionTask",
]
