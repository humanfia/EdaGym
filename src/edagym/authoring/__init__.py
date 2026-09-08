"""Public contracts for restricted task authoring providers."""

from edagym.authoring.contracts import (
    AuthoringContractReceipt,
    CatalogVerificationProjection,
    parse_authoring_contract_output,
    parse_catalog_verification_output,
)
from edagym.authoring.determinism import (
    AuthoringDeterminismReceipt,
    VerifiedAuthoringDeterminism,
    verify_determinism,
)
from edagym.authoring.factory import (
    GeneratedTask,
    GenerationRequest,
    Qualifier,
    TaskFactory,
    generate_task,
)
from edagym.authoring.materialization import (
    CatalogMaterializationReceipt,
    materialize_private_catalog,
    verify_materialized_catalog,
)
from edagym.authoring.provider import (
    AuthoringProviderError,
    CandidateSubmission,
    CleanRoomCatalogAttestation,
    CleanRoomFamilyProjection,
    DerivedTaskDocument,
    ExternalAuthoringProvider,
    FlowCandidateAttestation,
    FlowCandidateInventory,
    OpaqueTaskInstanceReference,
    PrivateAuthoringCapability,
    PrivateDerivationScope,
    PrivateProviderSecurityQualification,
    SealedCatalogAttestation,
    SealedFamilyAttestation,
    SealedInstanceQualification,
    authoring_provider_schema_digest,
)
from edagym.authoring.public_benchmarks import import_public_calibration_task
from edagym.authoring.qualification import (
    qualify_from_canaries,
)
from edagym.specs.release import TaskCanaryObservation

__all__ = [
    "AuthoringContractReceipt",
    "AuthoringDeterminismReceipt",
    "AuthoringProviderError",
    "CandidateSubmission",
    "CatalogMaterializationReceipt",
    "CatalogVerificationProjection",
    "CleanRoomCatalogAttestation",
    "CleanRoomFamilyProjection",
    "DerivedTaskDocument",
    "ExternalAuthoringProvider",
    "FlowCandidateAttestation",
    "FlowCandidateInventory",
    "GeneratedTask",
    "GenerationRequest",
    "OpaqueTaskInstanceReference",
    "PrivateAuthoringCapability",
    "PrivateDerivationScope",
    "PrivateProviderSecurityQualification",
    "Qualifier",
    "SealedCatalogAttestation",
    "SealedFamilyAttestation",
    "SealedInstanceQualification",
    "TaskCanaryObservation",
    "TaskFactory",
    "VerifiedAuthoringDeterminism",
    "authoring_provider_schema_digest",
    "generate_task",
    "import_public_calibration_task",
    "materialize_private_catalog",
    "parse_authoring_contract_output",
    "parse_catalog_verification_output",
    "qualify_from_canaries",
    "verify_determinism",
    "verify_materialized_catalog",
]
