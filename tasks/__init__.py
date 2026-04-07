from .sql_injection           import SQLInjectionTask
from .spearphish_credential   import SpearphishCredentialTask
from .cloud_identity_intrusion import CloudIdentityIntrusionTask
from .ai_tool_exploitation     import AIToolExploitationTask

# Registry: task_id → class
TASK_REGISTRY = {
    SQLInjectionTask.TASK_ID:          SQLInjectionTask,
    SpearphishCredentialTask.TASK_ID:  SpearphishCredentialTask,
    CloudIdentityIntrusionTask.TASK_ID: CloudIdentityIntrusionTask,
    AIToolExploitationTask.TASK_ID:    AIToolExploitationTask,
}

__all__ = [
    "TASK_REGISTRY",
    "SQLInjectionTask",
    "SpearphishCredentialTask",
    "CloudIdentityIntrusionTask",
    "AIToolExploitationTask",
]
