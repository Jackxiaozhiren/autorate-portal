"""Section 6.3's fixture list: a literal, not a glob.

It lives in the package rather than in the tool so that a plant can mutate it
and the parity test can go red. A glob here would pass when an artefact is
absent, which is precisely the failure the parity job exists to prevent.
"""

_NAMES = (
    "data/cert_jev.json",
    "data/cert_laya.json",
    "data/cert_massive_de_laya.json",
    "data/cert_massive_en_laya.json",
    "data/cert_massive_km_laya.json",
    "data/cert_massive_sw_laya.json",
    "data/cert_severity_ordinal.json",
)

_SLICE_NAMES = ("data/slices_language.json",)

ARTEFACTS: tuple[str, ...] = tuple(_NAMES)
SLICE_ARTEFACTS: tuple[str, ...] = tuple(_SLICE_NAMES)
ALL_ARTEFACTS: tuple[str, ...] = ARTEFACTS + SLICE_ARTEFACTS
