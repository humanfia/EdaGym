"""Canonical inventory of concrete backend commands considered by EdaGym."""

from __future__ import annotations

from collections.abc import Mapping

from edagym.drivers.model import (
    BackendCatalog,
    BackendDefinition,
    CapabilityFixture,
    HostSupportMode,
    Vendor,
    qualification_fixture_id,
)
from edagym.specs.common import Capability


def _definition(
    tool_id: str,
    vendor: Vendor,
    capabilities: tuple[Capability, ...],
    executables: tuple[str, ...],
    version_arguments: tuple[str, ...],
    fixture_capabilities: tuple[Capability, ...] = (),
    *,
    host_support_mode: HostSupportMode = HostSupportMode.DEFAULT,
    version_identity_pattern: str | None = None,
    accepted_version_exit_codes: tuple[int, ...] = (0,),
    workload_use_requires_eula_acceptance: bool = False,
    implementation_family_overrides: Mapping[Capability, str] | None = None,
) -> BackendDefinition:
    implementation_families = (
        {} if implementation_family_overrides is None else implementation_family_overrides
    )
    return BackendDefinition(
        tool_id=tool_id,
        vendor=vendor,
        capabilities=capabilities,
        executable_candidates=executables,
        version_arguments=version_arguments,
        accepted_version_exit_codes=accepted_version_exit_codes,
        version_identity_pattern=version_identity_pattern,
        workload_use_requires_eula_acceptance=workload_use_requires_eula_acceptance,
        host_support_mode=host_support_mode,
        fixtures=tuple(
            CapabilityFixture(
                capability=capability,
                fixture_id=qualification_fixture_id(tool_id, capability),
                implementation_family=implementation_families.get(capability, tool_id),
            )
            for capability in fixture_capabilities
        ),
    )


BACKENDS: tuple[BackendDefinition, ...] = (
    _definition(
        "iverilog",
        Vendor.OPEN_SOURCE,
        (Capability.RTL_SIMULATION,),
        ("iverilog",),
        ("-V",),
        (Capability.RTL_SIMULATION,),
    ),
    _definition(
        "verilator",
        Vendor.OPEN_SOURCE,
        (Capability.RTL_SIMULATION, Capability.RTL_LINT),
        ("verilator",),
        ("--version",),
        (Capability.RTL_SIMULATION, Capability.RTL_LINT),
    ),
    _definition(
        "yosys",
        Vendor.OPEN_SOURCE,
        (Capability.ASIC_SYNTHESIS, Capability.EQUIVALENCE, Capability.FORMAL_PROPERTY),
        ("yosys",),
        ("-V",),
        (Capability.ASIC_SYNTHESIS, Capability.EQUIVALENCE, Capability.FORMAL_PROPERTY),
        implementation_family_overrides={Capability.FORMAL_PROPERTY: "yosys-smt"},
    ),
    _definition(
        "abc",
        Vendor.OPEN_SOURCE,
        (Capability.ASIC_SYNTHESIS, Capability.EQUIVALENCE),
        ("yosys-abc",),
        ("-c", "version"),
        (Capability.ASIC_SYNTHESIS, Capability.EQUIVALENCE),
    ),
    _definition(
        "firtool",
        Vendor.OPEN_SOURCE,
        (Capability.HW_IR_LOWERING,),
        ("firtool",),
        ("--version",),
        (Capability.HW_IR_LOWERING,),
    ),
    _definition(
        "openroad",
        Vendor.OPEN_SOURCE,
        (
            Capability.STATIC_TIMING,
            Capability.DIGITAL_IMPLEMENTATION,
            Capability.POWER_ANALYSIS,
            Capability.POWER_INTEGRITY,
            Capability.PARASITIC_EXTRACTION,
        ),
        ("openroad",),
        ("-version",),
        (
            Capability.STATIC_TIMING,
            Capability.DIGITAL_IMPLEMENTATION,
            Capability.POWER_ANALYSIS,
            Capability.POWER_INTEGRITY,
            Capability.PARASITIC_EXTRACTION,
        ),
        implementation_family_overrides={Capability.STATIC_TIMING: "opensta"},
    ),
    _definition(
        "klayout",
        Vendor.OPEN_SOURCE,
        (Capability.PHYSICAL_VERIFICATION,),
        ("klayout",),
        ("-v",),
        (Capability.PHYSICAL_VERIFICATION,),
    ),
    _definition(
        "ngspice",
        Vendor.OPEN_SOURCE,
        (Capability.CIRCUIT_SIMULATION, Capability.CELL_CHARACTERIZATION),
        ("ngspice",),
        ("--version",),
        (Capability.CIRCUIT_SIMULATION, Capability.CELL_CHARACTERIZATION),
    ),
    _definition(
        "xcelium",
        Vendor.CADENCE,
        (Capability.RTL_SIMULATION,),
        ("xrun",),
        ("-version",),
        (Capability.RTL_SIMULATION,),
    ),
    _definition(
        "genus",
        Vendor.CADENCE,
        (Capability.ASIC_SYNTHESIS,),
        ("genus",),
        ("-version",),
        (Capability.ASIC_SYNTHESIS,),
        version_identity_pattern=(
            r"^Program Name: Genus\(TM\) Synthesis Solution, Version: [^\r\n]+"
        ),
    ),
    _definition(
        "jaspergold",
        Vendor.CADENCE,
        (Capability.FORMAL_PROPERTY, Capability.CDC_RDC),
        ("jg", "jaspergold"),
        ("-allow_unsupported_OS", "-version"),
        (Capability.FORMAL_PROPERTY, Capability.CDC_RDC),
        host_support_mode=HostSupportMode.VENDOR_UNSUPPORTED_OVERRIDE,
    ),
    _definition(
        "conformal",
        Vendor.CADENCE,
        (Capability.EQUIVALENCE,),
        ("lec",),
        ("-version",),
        (Capability.EQUIVALENCE,),
        version_identity_pattern=r"^Tool:[ \t]+lec[ \t]+[^\r\n]+",
    ),
    _definition(
        "innovus",
        Vendor.CADENCE,
        (Capability.DIGITAL_IMPLEMENTATION,),
        ("innovus",),
        ("-version",),
        (Capability.DIGITAL_IMPLEMENTATION,),
        version_identity_pattern=r"^@\(#\)CDS: Innovus [^\r\n]+",
    ),
    _definition(
        "tempus",
        Vendor.CADENCE,
        (Capability.STATIC_TIMING,),
        ("tempus",),
        ("-version",),
        (Capability.STATIC_TIMING,),
        version_identity_pattern=r"^@\(#\)CDS: Tempus Timing Solution [^\r\n]+",
    ),
    _definition(
        "voltus",
        Vendor.CADENCE,
        (Capability.POWER_INTEGRITY,),
        ("voltus",),
        ("-version",),
    ),
    _definition(
        "joules",
        Vendor.CADENCE,
        (Capability.POWER_ANALYSIS,),
        ("joules",),
        ("-version",),
    ),
    _definition(
        "quantus",
        Vendor.CADENCE,
        (Capability.PARASITIC_EXTRACTION,),
        ("qrc", "quantus"),
        ("-version",),
    ),
    _definition(
        "spectre",
        Vendor.CADENCE,
        (Capability.CIRCUIT_SIMULATION,),
        ("spectre",),
        ("-W",),
        (Capability.CIRCUIT_SIMULATION,),
    ),
    _definition(
        "pegasus",
        Vendor.CADENCE,
        (Capability.PHYSICAL_VERIFICATION,),
        ("pegasus",),
        ("-version",),
        (Capability.PHYSICAL_VERIFICATION,),
        version_identity_pattern=(r"^Pegasus [0-9][A-Za-z0-9._-]* [A-Za-z0-9+/]+(?= )"),
    ),
    _definition(
        "modus",
        Vendor.CADENCE,
        (Capability.DESIGN_FOR_TEST,),
        ("modus",),
        ("-version",),
        (Capability.DESIGN_FOR_TEST,),
    ),
    _definition(
        "liberate",
        Vendor.CADENCE,
        (Capability.CELL_CHARACTERIZATION,),
        ("liberate",),
        ("-version",),
    ),
    _definition(
        "stratus",
        Vendor.CADENCE,
        (Capability.HIGH_LEVEL_SYNTHESIS,),
        ("stratus",),
        ("-version",),
    ),
    _definition(
        "vcs",
        Vendor.SYNOPSYS,
        (Capability.RTL_SIMULATION,),
        ("vcs",),
        ("-full64", "-ID"),
        (Capability.RTL_SIMULATION,),
        host_support_mode=HostSupportMode.VENDOR_UNSUPPORTED,
    ),
    _definition(
        "design_compiler",
        Vendor.SYNOPSYS,
        (Capability.ASIC_SYNTHESIS,),
        ("dc_shell",),
        ("-x", "puts $synopsys_program_version; exit"),
        (Capability.ASIC_SYNTHESIS,),
        version_identity_pattern=r"^[ \t]*Version [^\r\n]+",
    ),
    _definition(
        "formality",
        Vendor.SYNOPSYS,
        (Capability.EQUIVALENCE,),
        ("fm_shell",),
        ("-version",),
        (Capability.EQUIVALENCE,),
        version_identity_pattern=r"^Formality \(R\)  Version [^\r\n]+",
    ),
    _definition(
        "vc_formal",
        Vendor.SYNOPSYS,
        (Capability.FORMAL_PROPERTY,),
        ("vcf", "vc_formal"),
        ("-ID",),
        (Capability.FORMAL_PROPERTY,),
        version_identity_pattern=r"^Version[ \t]+->[ \t]+[^\r\n]+",
    ),
    _definition(
        "spyglass",
        Vendor.SYNOPSYS,
        (Capability.RTL_LINT, Capability.CDC_RDC),
        ("spyglass",),
        ("-version",),
        (Capability.RTL_LINT, Capability.CDC_RDC),
    ),
    _definition(
        "primetime",
        Vendor.SYNOPSYS,
        (Capability.STATIC_TIMING, Capability.POWER_ANALYSIS),
        ("pt_shell",),
        ("-version",),
        (Capability.STATIC_TIMING,),
        version_identity_pattern=r"^pt_shell version[ \t]+-[ \t]+[^\r\n]+",
    ),
    _definition(
        "icc2",
        Vendor.SYNOPSYS,
        (Capability.DIGITAL_IMPLEMENTATION,),
        ("icc2_shell",),
        ("-version",),
        (Capability.DIGITAL_IMPLEMENTATION,),
        version_identity_pattern=r"^icc2_shell version [^\r\n]+",
    ),
    _definition(
        "fusion_compiler",
        Vendor.SYNOPSYS,
        (Capability.ASIC_SYNTHESIS, Capability.DIGITAL_IMPLEMENTATION),
        ("fc_shell",),
        ("-version",),
    ),
    _definition(
        "hspice",
        Vendor.SYNOPSYS,
        (Capability.CIRCUIT_SIMULATION,),
        ("hspice",),
        ("-v",),
        (Capability.CIRCUIT_SIMULATION,),
    ),
    _definition(
        "starrc",
        Vendor.SYNOPSYS,
        (Capability.PARASITIC_EXTRACTION,),
        ("StarXtract", "starrc"),
        ("-v",),
        accepted_version_exit_codes=(0, 1),
        version_identity_pattern=(
            r"^Version:[ \t]+[A-Z]-[0-9]{4}\.[0-9]{2}(?:-SP[0-9]+)?"
            r"(?=\r?\nBuilt on:[^\r\n]+\r?\nStart Time:)"
        ),
    ),
    _definition(
        "ic_validator",
        Vendor.SYNOPSYS,
        (Capability.PHYSICAL_VERIFICATION,),
        ("icv",),
        ("-V",),
        (Capability.PHYSICAL_VERIFICATION,),
    ),
    _definition(
        "testmax",
        Vendor.SYNOPSYS,
        (Capability.DESIGN_FOR_TEST,),
        ("tmax", "testmax"),
        ("-shell", "-version"),
    ),
    _definition(
        "siliconsmart",
        Vendor.SYNOPSYS,
        (Capability.CELL_CHARACTERIZATION,),
        ("SiliconSmart", "siliconsmart"),
        ("-version",),
    ),
    _definition(
        "vivado",
        Vendor.AMD,
        (Capability.FPGA_IMPLEMENTATION,),
        ("vivado",),
        ("-version",),
        (Capability.FPGA_IMPLEMENTATION,),
    ),
    _definition(
        "vitis_hls",
        Vendor.AMD,
        (Capability.HIGH_LEVEL_SYNTHESIS,),
        ("vitis-run",),
        ("--version",),
        (Capability.HIGH_LEVEL_SYNTHESIS,),
        version_identity_pattern=(r"^\*{6} vitis-run v[0-9][A-Za-z0-9._-]* \(64-bit\)$"),
    ),
    _definition(
        "quartus",
        Vendor.ALTERA,
        (Capability.FPGA_IMPLEMENTATION,),
        ("quartus_sh",),
        ("--version",),
        (Capability.FPGA_IMPLEMENTATION,),
    ),
    _definition(
        "nextpnr_ice40",
        Vendor.OPEN_SOURCE,
        (Capability.FPGA_IMPLEMENTATION,),
        ("nextpnr-ice40",),
        ("--version",),
        (Capability.FPGA_IMPLEMENTATION,),
        version_identity_pattern=(
            r'^"nextpnr-ice40" -- Next Generation Place and Route '
            r"\(Version [0-9][A-Za-z0-9.+-]*\)$"
        ),
    ),
    _definition(
        "achronix_ace",
        Vendor.ACHRONIX,
        (Capability.FPGA_IMPLEMENTATION,),
        ("ace", "ace_run"),
        ("--version",),
        workload_use_requires_eula_acceptance=True,
    ),
)

BACKEND_CATALOG = BackendCatalog(backends=BACKENDS)
BACKENDS = BACKEND_CATALOG.backends


def backend_by_id(tool_id: str) -> BackendDefinition:
    matches = [backend for backend in BACKENDS if backend.tool_id == tool_id]
    if len(matches) != 1:
        raise KeyError(tool_id)
    return matches[0]


def validate_catalog() -> None:
    """Assert unique backend ownership and complete logical capability coverage."""

    from edagym.drivers.fixtures.catalog import QUALIFICATION_FIXTURES

    tool_ids = [backend.tool_id for backend in BACKENDS]
    if len(tool_ids) != len(set(tool_ids)):
        raise ValueError("backend catalog contains duplicate tool identifiers")
    covered = {capability for backend in BACKENDS for capability in backend.capabilities}
    if covered != set(Capability):
        missing = sorted(capability.value for capability in set(Capability) - covered)
        raise ValueError(f"backend catalog does not cover capabilities: {missing!r}")
    declared_fixtures = {
        (backend.tool_id, fixture.capability, fixture.fixture_id)
        for backend in BACKENDS
        for fixture in backend.fixtures
    }
    implemented_fixtures = {
        (fixture.tool_id, fixture.capability, fixture.fixture_id)
        for fixture in QUALIFICATION_FIXTURES
    }
    if declared_fixtures != implemented_fixtures:
        raise ValueError("backend fixture declarations must exactly match their implementations")
    definitions = {backend.tool_id: backend for backend in BACKENDS}
    unsafe_commercial = [
        fixture.fixture_id
        for fixture in QUALIFICATION_FIXTURES
        if definitions[fixture.tool_id].vendor is not Vendor.OPEN_SOURCE
        and (fixture.log_projection is None or not fixture.rejection_inputs)
    ]
    if unsafe_commercial:
        raise ValueError(
            "commercial qualification fixtures require marker-projected logs and paired inputs"
        )


validate_catalog()
