"""
Environment profiles  (situational scoring)
===========================================

The same attack step is not equally risky everywhere. Dumping LSASS is
near-suicidal in an EDR-heavy estate but routine in a legacy domain with
no endpoint logging. DCSync screams in a SOC that audits directory
replication (event 4662) and whispers in one that doesn't.

A *profile* models one of these situations. It nudges each technique's
DETECTION (how loud) and RELIABILITY (how dependable) by a per-CATEGORY
multiplier, so the SAME graph produces DIFFERENT rankings depending on
where you are. That is the "react to the situation and change
accordingly" behaviour: pick a profile and PathHunter re-prioritises.

Profiles change scoring ONLY. They never touch the graph or the frontend.

Usage (backend):
    from pathhunter.profiles import get_profile_technique
    t = get_profile_technique("HasSession", "edr")   # much louder than default

CLI:
    python -m pathhunter --start alice --target daadmin --profile edr
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .techniques import CATEGORIES, Technique, get_technique


@dataclass(frozen=True)
class Profile:
    """A situational scoring lens.

    `detection` / `reliability` map a technique CATEGORY to a multiplier.
    Anything not listed defaults to 1.0 (unchanged). Detection multipliers
    above 1.0 make that family louder; below 1.0 make it quieter.
    """

    name: str
    description: str
    detection: dict[str, float] = field(default_factory=dict)
    reliability: dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# The built-in profiles. Multipliers are deliberately conservative so the
# ordering shifts meaningfully without any single edge dominating.
# ---------------------------------------------------------------------------
PROFILES: dict[str, Profile] = {
    "default": Profile(
        "default", "Baseline scoring as published in the knowledge base."),

    # Modern estate: EDR on endpoints + a SOC that watches the directory.
    # Touching memory / replicating secrets / cert forgery is very risky;
    # reliability of memory-based theft drops because EDR blocks it.
    "edr": Profile(
        "edr",
        "EDR on endpoints + directory auditing: credential theft, "
        "replication, lateral exec and cert abuse are far louder.",
        detection={
            "credential": 1.6,
            "replication": 1.4,
            "lateral": 1.3,
            "certificate": 1.3,
            "kerberos": 1.2,
        },
        reliability={
            "credential": 0.7,   # EDR often blocks LSASS access outright
            "lateral": 0.9,
        },
    ),

    # Legacy / under-instrumented domain: little endpoint or directory
    # logging, so noisy techniques are effectively quiet, and old reliable
    # lateral movement just works.
    "legacy": Profile(
        "legacy",
        "Legacy estate, minimal logging: most techniques are much quieter "
        "and old-school lateral movement is highly reliable.",
        detection={
            "credential": 0.5,
            "replication": 0.6,
            "lateral": 0.7,
            "acl": 0.8,
            "certificate": 0.7,
            "kerberos": 0.8,
        },
        reliability={
            "lateral": 1.05,
            "credential": 1.05,
        },
    ),

    # Audit-heavy directory (object-access auditing / 4662 everywhere) but
    # NOT necessarily endpoint EDR: ACL writes, replication and cert
    # enrollment are loud; pure host credential theft is comparatively less
    # amplified than under 'edr'.
    "audited": Profile(
        "audited",
        "Directory object-access auditing (4662) on: ACL writes, "
        "replication and certificate enrollment are loud.",
        detection={
            "acl": 1.4,
            "replication": 1.5,
            "certificate": 1.4,
            "delegation": 1.2,
            "kerberos": 1.2,
        },
    ),
}


def list_profiles() -> list[str]:
    """Names of the available profiles (for CLI choices / help)."""
    return list(PROFILES)


def get_profile(name: str | None) -> Profile:
    """Return a Profile by name, falling back to 'default' if unknown/None."""
    if not name:
        return PROFILES["default"]
    return PROFILES.get(name, PROFILES["default"])


def _clamp_detection(value: float) -> int:
    """Keep detection an int in the 1..10 band the rest of the tool expects."""
    return max(1, min(10, round(value)))


def _clamp_reliability(value: float) -> float:
    """Keep reliability a float in the 0.0..1.0 band."""
    return round(max(0.0, min(1.0, value)), 3)


def adjust_technique(t: Technique, profile: Profile | str | None) -> Technique:
    """Return a copy of `t` with detection/reliability shifted by the profile.

    The 'default' profile returns the technique unchanged. Structural edges
    are left alone (they are not attacker actions, so the situation does not
    make them louder).
    """
    prof = profile if isinstance(profile, Profile) else get_profile(profile)
    if prof.name == "default" or t.category == "structural":
        return t

    det_mult = prof.detection.get(t.category, 1.0)
    rel_mult = prof.reliability.get(t.category, 1.0)
    if det_mult == 1.0 and rel_mult == 1.0:
        return t

    # replace() copies every other field (note/opsec/remediation/references)
    # so enrichment survives the profile adjustment.
    return replace(
        t,
        detection=_clamp_detection(t.detection * det_mult),
        reliability=_clamp_reliability(t.reliability * rel_mult),
    )


def get_profile_technique(edge_kind: str, profile: Profile | str | None) -> Technique:
    """Convenience: look up an edge's technique and apply a profile in one go."""
    return adjust_technique(get_technique(edge_kind), profile)
