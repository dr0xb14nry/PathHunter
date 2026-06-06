"""
Technique knowledge base  (Phase 2, enriched)
=============================================

This is the "brain food" for PathHunter.

Every relationship (edge) in a BloodHound graph corresponds to a real
attack technique. This file maps each edge type to:

  * a human-readable technique name
  * its MITRE ATT&CK id (so reports speak the industry's language)
  * a DETECTION score   -> how LOUD it is (1 = silent, 10 = very loud)
  * a RELIABILITY score  -> how dependable it is (0.0 = flaky, 1.0 = rock solid)
  * a CATEGORY            -> the family of the technique (used by env profiles)
  * a short NOTE          -> *why* it's noisy / how it actually works

WHY THESE NUMBERS AREN'T MADE UP
--------------------------------
The detection score is grounded in the Windows telemetry each technique
generates (logon events, password-reset events, LSASS access, AD
replication, certificate enrollment, etc.). That grounding is what makes
the tool credible to a real red/blue teamer instead of looking like
guesswork.

These scores feed two things:
  1. the path ranking (fastest / stealthiest / most reliable), and
  2. the environment PROFILES (see profiles.py), which shift the scores
     to model *different situations* -- e.g. an EDR-heavy estate makes
     credential theft far louder, while a legacy under-logged domain
     makes everything quieter.

DATA SOURCES (refresh with scripts/fetch_techniques.py)
-------------------------------------------------------
  * BloodHound CE edge reference  (SpecterOps docs: the edge names below
    match the exact "kind" strings SharpHound / BloodHound CE emit).
  * MITRE ATT&CK Enterprise       (technique ids; names verifiable via
    the fetch script against the official MITRE CTI dataset).
  * Microsoft Windows security auditing (event ids cited in the notes).
"""

from __future__ import annotations

from dataclasses import dataclass, replace


# Technique families. Environment profiles (profiles.py) adjust detection
# and reliability per-family, so keep these stable -- they are the join key.
CATEGORIES = (
    "membership",    # you already hold the right; structural
    "acl",           # DACL / object-permission abuse
    "kerberos",      # kerberoast / asrep / targeted SPN abuse
    "delegation",    # constrained / RBCD / unconstrained delegation
    "lateral",       # remote code execution / lateral movement
    "credential",    # credential theft from a host or directory
    "replication",   # DCSync / directory replication
    "certificate",   # AD CS (ESCx) abuse
    "trust",         # domain/forest trust abuse
    "structural",    # not an attacker action on its own (Contains, links)
)


@dataclass(frozen=True)
class Technique:
    """One attack technique tied to a BloodHound edge type."""

    name: str           # human-readable technique
    mitre: str          # MITRE ATT&CK id (e.g. "T1003.006")
    detection: int      # 1 (silent) .. 10 (very loud)
    reliability: float  # 0.0 (flaky) .. 1.0 (rock solid)
    category: str = "acl"          # one of CATEGORIES (drives env profiles)
    note: str = ""                 # why it's detectable / how it works
    opsec: str = ""                # red-team operational-security guidance
    remediation: str = ""          # blue-team fix / hardening
    references: tuple[str, ...] = ()   # authoritative sources for this edge


# ---------------------------------------------------------------------------
# The knowledge base: BloodHound edge "kind"  ->  Technique
# Ordered by where they tend to appear in an attack:
#   membership/structural -> ACL abuse -> kerberos -> delegation ->
#   lateral movement -> credential theft -> replication -> AD CS -> trusts.
# ---------------------------------------------------------------------------
TECHNIQUES: dict[str, Technique] = {
    # ----- membership / structural (free, silent) -----
    "MemberOf": Technique(
        "Group membership (inherited rights)", "T1078", 1, 1.00, "membership",
        "No action needed - you simply belong to the group. Silent."),
    "Contains": Technique(
        "OU/Container containment", "-", 1, 1.00, "structural",
        "Structural AD containment; meaningful only with GPO abuse."),
    "GpLink": Technique(
        "GPO linked to an OU/domain", "T1484.001", 2, 0.80, "structural",
        "A linked GPO can push policy/scripts to everything beneath it."),
    "HasSIDHistory": Technique(
        "SID history grants another principal's rights", "T1134.005", 2, 0.95,
        "membership",
        "Token carries an extra SID - rights apply with no extra action."),

    # ----- ACL abuse over an object -----
    "ForceChangePassword": Technique(
        "Reset a target account's password", "T1098", 4, 0.95, "acl",
        "Generates a password-reset event (4724). Reliable but logged."),
    "AddMember": Technique(
        "Add yourself to a privileged group", "T1098", 3, 0.95, "acl",
        "Group-membership change (4728/4732). Easy and reliable."),
    "AddSelf": Technique(
        "Add yourself to a group you can write", "T1098", 3, 0.95, "acl",
        "Self-membership write (4728/4732). Quiet and reliable."),
    "GenericAll": Technique(
        "Full control over object (many abuses)", "T1098", 4, 0.90, "acl",
        "Lets you reset passwords, set SPNs, or add shadow credentials."),
    "GenericWrite": Technique(
        "Write key attributes (targeted abuse)", "T1098", 4, 0.85, "acl",
        "Enables targeted Kerberoast or shadow-credential attacks."),
    "AllExtendedRights": Technique(
        "All extended rights (incl. password reset)", "T1098", 4, 0.85, "acl",
        "Bundles sensitive rights like ForceChangePassword/DCSync."),
    "WriteDacl": Technique(
        "Rewrite the object's permissions (DACL)", "T1222.001", 5, 0.80, "acl",
        "Grant yourself GenericAll first, then abuse it. Two-step."),
    "WriteOwner": Technique(
        "Take ownership of the object", "T1222.001", 5, 0.80, "acl",
        "Become owner, then rewrite the DACL. Two-step."),
    "Owns": Technique(
        "Already the object owner", "T1222.001", 4, 0.85, "acl",
        "Ownership lets you change permissions at will."),
    "WriteAccountRestrictions": Technique(
        "Write account restriction attributes", "T1098", 4, 0.75, "acl",
        "Flip flags (e.g. disable preauth) to enable other attacks."),
    "AddKeyCredentialLink": Technique(
        "Shadow Credentials", "T1556", 4, 0.90, "acl",
        "Add a fake key to log on as the target (Whisker/Certipy)."),
    "WriteSPN": Technique(
        "Set an SPN to enable targeted Kerberoast", "T1558.003", 5, 0.80,
        "kerberos",
        "Write servicePrincipalName, then Kerberoast the account (4769)."),
    "WriteGPLink": Technique(
        "Link a malicious GPO to an OU/domain", "T1484.001", 5, 0.70,
        "acl",
        "Push a startup/script policy to all objects beneath the link."),
    "AddAllowedToAct": Technique(
        "Configure RBCD on the target", "T1098", 5, 0.75, "delegation",
        "Write msDS-AllowedToActOnBehalfOfOtherIdentity, then impersonate."),

    # ----- kerberos roasting (capability edges / derived) -----
    "Kerberoastable": Technique(
        "Kerberoast an SPN account offline", "T1558.003", 6, 0.80, "kerberos",
        "Request a service ticket (4769) and crack it offline."),
    "ASREPRoastable": Technique(
        "AS-REP roast a preauth-disabled account", "T1558.004", 6, 0.75,
        "kerberos",
        "Grab the AS-REP (4768) for an account without preauth, crack offline."),
    "CoerceToTGT": Technique(
        "Coerce/abuse to obtain the target's TGT", "T1558", 6, 0.70, "kerberos",
        "Force authentication or abuse delegation to capture a usable TGT."),

    # ----- delegation abuse -----
    "AllowedToDelegate": Technique(
        "Constrained delegation abuse (S4U2Proxy)", "T1558.003", 6, 0.70,
        "delegation",
        "Impersonate users to a service. Anomalous tickets (4769)."),
    "AllowedToAct": Technique(
        "Resource-based constrained delegation (RBCD)", "T1134", 5, 0.75,
        "delegation",
        "Set msDS-AllowedToActOnBehalf, then impersonate. Medium noise."),

    # ----- lateral movement (needed for remote exec) -----
    "AdminTo": Technique(
        "Local admin -> remote code execution (PsExec/WMI)", "T1021", 5, 0.90,
        "lateral",
        "Creates a service / type-3 logon (7045, 4624). Medium noise."),
    "CanRDP": Technique(
        "Remote Desktop access", "T1021.001", 4, 0.90, "lateral",
        "Interactive logon (4624 type 10). Common, moderate noise."),
    "CanPSRemote": Technique(
        "PowerShell Remoting (WinRM)", "T1021.006", 4, 0.85, "lateral",
        "WinRM logon, visible in PowerShell/WinRM logs."),
    "ExecuteDCOM": Technique(
        "Lateral movement via DCOM", "T1021.003", 5, 0.70, "lateral",
        "DCOM activation events; less reliable across configs."),
    "SQLAdmin": Technique(
        "SQL Server admin -> code execution", "T1190", 6, 0.70, "lateral",
        "xp_cmdshell and friends. Depends on SQL configuration."),

    # ----- credential theft -----
    "HasSession": Technique(
        "Steal credentials from a live session (LSASS)", "T1003.001", 9, 0.85,
        "credential",
        "Touching LSASS is heavily watched by EDR (Sysmon 10). Very loud."),
    "ReadLAPSPassword": Technique(
        "Read the local admin password from LAPS", "T1555", 3, 0.95,
        "credential",
        "Reads ms-Mcs-AdmPwd / msLAPS-Password. Quiet unless 4662 auditing."),
    "ReadGMSAPassword": Technique(
        "Read a gMSA managed password", "T1555", 3, 0.95, "credential",
        "Reads msDS-ManagedPassword and derives the account's key. Quiet."),
    "DumpSMSAPassword": Technique(
        "Dump a standalone MSA password from a host", "T1003", 4, 0.85,
        "credential",
        "Requires host access; recovers the sMSA secret locally."),
    "SyncLAPSPassword": Technique(
        "Replicate LAPS passwords from the directory", "T1003.006", 4, 0.90,
        "credential",
        "Uses replication rights scoped to LAPS attributes. Event 4662."),

    # ----- replication / domain takeover (DCSync) -----
    # Either replication right alone is useless; you need both GetChanges and
    # GetChangesAll. We score each as the DCSync technique so a path that
    # collects both lands on it.
    "GetChanges": Technique(
        "DCSync replication right (1 of 2)", "T1003.006", 9, 0.90, "replication",
        "With GetChangesAll this becomes full DCSync. Event 4662. Loud."),
    "GetChangesAll": Technique(
        "DCSync replication right (2 of 2)", "T1003.006", 9, 0.90, "replication",
        "With GetChanges this becomes full DCSync. Event 4662. Loud."),
    "GetChangesInFilteredSet": Technique(
        "Replicate the filtered attribute set", "T1003.006", 8, 0.85,
        "replication",
        "Part of some DCSync variants (e.g. RODC/LAPS). Event 4662."),
    "DCSync": Technique(
        "DCSync - dump all domain password hashes", "T1003.006", 9, 0.90,
        "replication",
        "Replicate secrets straight from the DC. Powerful but very logged."),

    # ----- AD CS (Active Directory Certificate Services) abuse -----
    # MITRE T1649 "Steal or Forge Authentication Certificates".
    "Enroll": Technique(
        "Enroll for a certificate template", "T1649", 4, 0.80, "certificate",
        "Certificate request/issue events (4886/4887) on the CA."),
    "ADCSESC1": Technique(
        "ESC1: enrollee-supplies-subject -> auth as anyone", "T1649", 5, 0.85,
        "certificate",
        "Request a cert with an arbitrary SAN, then auth as that user."),
    "ADCSESC3": Technique(
        "ESC3: enrollment agent cert -> request on behalf", "T1649", 5, 0.80,
        "certificate",
        "Use an enrollment-agent cert to request for another principal."),
    "ADCSESC4": Technique(
        "ESC4: writable template -> make it vulnerable", "T1649", 5, 0.80,
        "certificate",
        "Edit the template ACL/flags, then enroll (becomes ESC1)."),
    "ADCSESC6a": Technique(
        "ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 abuse", "T1649", 6, 0.75,
        "certificate",
        "CA-wide SAN injection regardless of template. Strong but CA-scoped."),
    "ADCSESC6b": Technique(
        "ESC6 (b variant): SAN injection + auth", "T1649", 6, 0.75,
        "certificate",
        "Same CA misconfig path, alternate prerequisites."),
    "ADCSESC9a": Technique(
        "ESC9: no-security-extension cert mapping", "T1649", 6, 0.75,
        "certificate",
        "Weak cert mapping lets a cert auth as a different account."),
    "ADCSESC9b": Technique(
        "ESC9 (b variant): no-security-extension", "T1649", 6, 0.75,
        "certificate",
        "Computer-account flavour of the ESC9 mapping abuse."),
    "ADCSESC10a": Technique(
        "ESC10: weak certificate mappings (a)", "T1649", 6, 0.70,
        "certificate",
        "Registry-based weak mapping enables cross-account auth."),
    "ADCSESC10b": Technique(
        "ESC10: weak certificate mappings (b)", "T1649", 6, 0.70,
        "certificate",
        "Alternate ESC10 prerequisite chain."),
    "ADCSESC13": Technique(
        "ESC13: issuance policy -> group rights", "T1649", 6, 0.75,
        "certificate",
        "Template OID linked to a group grants that group's access."),
    "ManageCA": Technique(
        "CA administrator -> issue/forge certificates", "T1649", 6, 0.80,
        "certificate",
        "CA admin can enable SAN, approve requests, or set ESC7 paths."),
    "ManageCertificates": Technique(
        "Certificate manager -> approve pending requests", "T1649", 5, 0.80,
        "certificate",
        "Approve an otherwise-denied request to obtain a cert."),
    "WritePKIEnrollmentFlag": Technique(
        "Write template enrollment flags", "T1649", 5, 0.75, "certificate",
        "Toggle flags to make a template enrollable/vulnerable."),
    "WritePKINameFlag": Technique(
        "Write template name flags (SAN)", "T1649", 5, 0.75, "certificate",
        "Enable enrollee-supplied subject to forge identity."),
    "DelegatedEnrollmentAgent": Technique(
        "Delegated enrollment agent rights", "T1649", 5, 0.75, "certificate",
        "Enroll on behalf of other principals via agent delegation."),
    "GoldenCert": Technique(
        "Steal CA key -> forge any certificate", "T1649", 7, 0.85, "certificate",
        "Exfiltrate the CA private key to mint certs offline (ESC region)."),

    # ----- trust abuse -----
    "SpoofSIDHistory": Technique(
        "Forge SID history across a trust", "T1134.005", 5, 0.80, "trust",
        "Inject privileged SIDs from a trusted/forest domain."),
    "AbuseTGTDelegation": Technique(
        "Abuse TGT delegation across a trust", "T1558", 6, 0.70, "trust",
        "Capture/relay a delegated TGT over an inbound trust."),
}


# Edges that are purely structural plumbing for AD CS / trusts. They are not
# attacker actions, so they're (almost) free and never look "risky" on their
# own -- but PathHunter still needs to traverse them.
_STRUCTURAL = {
    "DCFor", "EnterpriseCAFor", "RootCAFor", "TrustedForNTAuth",
    "NTAuthStoreFor", "IssuedSignedBy", "EnterpriseCA", "HostsCAService",
    "CanAbuseUPNCertMapping", "CanAbuseWeakCertBinding", "TrustKeyUsage",
    "SameForestTrust", "CrossForestTrust",
}
for _name in _STRUCTURAL:
    TECHNIQUES.setdefault(_name, Technique(
        f"{_name} (structural relationship)", "-", 1, 1.00, "structural",
        "Structural AD CS / trust plumbing; traversable but not an action."))


# Used for any edge type we haven't classified yet -- treated as medium risk
# so an unknown step never silently looks "safe".
UNKNOWN = Technique(
    "Unclassified relationship", "-", 5, 0.50, "acl",
    "Not yet in the knowledge base; treated as medium risk by default.")


# ===========================================================================
# Multi-source enrichment: per-technique OPSEC (red), remediation (blue), and
# authoritative references. We attach a sensible CATEGORY-level default to
# every edge, then override the high-value ones with edge-specific text.
#
# Sources (canonical, kept here so the fetch script can re-verify them):
#   SpecterOps BloodHound docs   https://bloodhound.specterops.io/resources/edges/
#   The Hacker Recipes           https://www.thehacker.recipes/ad/movement/
#   ired.team                    https://www.ired.team/offensive-security-experiments/
#   LOLBAS                       https://lolbas-project.github.io/
#   ADSecurity (Sean Metcalf)    https://adsecurity.org/
#   Certified Pre-Owned (ADCS)   https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
# ===========================================================================
SOURCES = {
    "specterops_edges": "https://bloodhound.specterops.io/resources/edges/",
    "hacker_recipes": "https://www.thehacker.recipes/ad/movement/",
    "ired": "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/",
    "lolbas": "https://lolbas-project.github.io/",
    "adsecurity": "https://adsecurity.org/",
    "certified_preowned": "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf",
}

CATEGORY_REFERENCES: dict[str, tuple[str, ...]] = {
    "membership": (SOURCES["specterops_edges"], SOURCES["hacker_recipes"]),
    "acl": (SOURCES["specterops_edges"], "https://www.thehacker.recipes/ad/movement/dacl/", SOURCES["ired"]),
    "kerberos": ("https://adsecurity.org/?p=3458", "https://www.thehacker.recipes/ad/movement/kerberos/"),
    "delegation": ("https://www.thehacker.recipes/ad/movement/kerberos/delegations", "https://dirkjanm.io/"),
    "lateral": (SOURCES["lolbas"], "https://www.thehacker.recipes/ad/movement/", SOURCES["specterops_edges"]),
    "credential": ("https://www.thehacker.recipes/ad/movement/credentials/dumping/", SOURCES["adsecurity"]),
    "replication": ("https://adsecurity.org/?p=1729", "https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"),
    "certificate": (SOURCES["certified_preowned"], "https://www.thehacker.recipes/ad/movement/ad-cs/", SOURCES["specterops_edges"]),
    "trust": ("https://www.thehacker.recipes/ad/movement/trusts", SOURCES["adsecurity"]),
    "structural": (SOURCES["specterops_edges"],),
}

CATEGORY_OPSEC: dict[str, str] = {
    "membership": "Passive - you simply hold the right. No telemetry; safe to ride.",
    "acl": "Writes to the object generate directory-change events (5136/4662 with SACLs). Revert the ACE after use.",
    "kerberos": "Request a single ticket and crack offline; avoid bulk 4769/4768 spikes and prefer accounts using RC4.",
    "delegation": "Produces anomalous service tickets (4769); clean up the delegation attribute you set afterwards.",
    "lateral": "Creates service/logon artifacts (7045, 4624 type 3/10) on the target; reuse native admin tooling to blend in.",
    "credential": "LSASS access is EDR-watched (Sysmon 10). Prefer directory-side secrets (LAPS/gMSA) or DPAPI when possible.",
    "replication": "Replication from a non-DC principal raises 4662. Run from DC context or accept high detection risk.",
    "certificate": "CA issuance is logged (4886/4887) and the issued cert persists in the CA store - expect retro-hunting.",
    "trust": "Cross-trust abuse is uncommon and stands out; confirm trust direction and SID filtering first.",
    "structural": "Not an attacker action on its own - no OPSEC concern.",
}

CATEGORY_REMEDIATION: dict[str, str] = {
    "membership": "Audit privileged group nesting; strip unnecessary transitive membership of Tier-0 groups.",
    "acl": "Tighten object DACLs; enable SACL auditing and alert on ACE additions (5136) to high-value objects.",
    "kerberos": "Use gMSA / long random passwords for SPN accounts, enforce AES, and alert on RC4 4769 requests.",
    "delegation": "Remove unneeded delegation; mark Tier-0 accounts 'sensitive and cannot be delegated'.",
    "lateral": "Restrict local admin with LAPS, enforce host firewalls, and monitor 4624 type 3/10 plus 7045.",
    "credential": "Enable Credential Guard / LSASS protection, rotate LAPS & gMSA, and restrict who may read them.",
    "replication": "Scope Get-Changes* rights to domain controllers only; alert on 4662 replication from non-DCs.",
    "certificate": "Remediate vulnerable templates (ESC1-13), enable CA auditing, and remove EDITF/SAN flags.",
    "trust": "Enable SID filtering on trusts and minimise cross-forest trust scope.",
    "structural": "No action required.",
}

# Edge-specific overrides where the generic category text isn't precise enough.
BESPOKE: dict[str, dict] = {
    "HasSession": {
        "opsec": "Dumping LSASS is one of the loudest moves you can make - Sysmon 10 / EDR will flag it. "
                 "Consider token impersonation or waiting for a less-monitored host.",
        "remediation": "Deploy Credential Guard and RunAsPPL for LSASS; limit interactive logons of Tier-0 accounts to PAWs.",
        "references": ("https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass",
                       "https://attack.mitre.org/techniques/T1003/001/"),
    },
    "DCSync": {
        "opsec": "Generates 4662 'Replicating Directory Changes' from a non-DC - a classic SOC alert. Target only the hashes you need.",
        "remediation": "Restrict DS-Replication-Get-Changes-All to DCs; alert on replication from any non-DC principal.",
        "references": ("https://adsecurity.org/?p=1729",
                       "https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"),
    },
    "ForceChangePassword": {
        "opsec": "Resetting the password locks out the legitimate user and emits 4724 - obvious. Re-set the original where feasible.",
        "remediation": "Limit who holds reset rights over Tier-0/-1 accounts; alert on 4724 against privileged users.",
        "references": ("https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword",
                       "https://bloodhound.specterops.io/resources/edges/force-change-password"),
    },
    "AddKeyCredentialLink": {
        "opsec": "Shadow Credentials are quiet (no password change) but the added key persists - remove the msDS-KeyCredentialLink entry after use.",
        "remediation": "Audit msDS-KeyCredentialLink writes; deploy and enforce strong certificate mapping (KB5014754).",
        "references": ("https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab",
                       "https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials"),
    },
    "ADCSESC1": {
        "opsec": "The requested cert is retained in the CA issued-certs store and ties the request to your principal + the impersonated SAN.",
        "remediation": "Remove ENROLLEE_SUPPLIES_SUBJECT from auth templates and require manager approval; audit issuance.",
        "references": (SOURCES["certified_preowned"],
                       "https://bloodhound.specterops.io/resources/edges/adcs-esc1"),
    },
    "GoldenCert": {
        "opsec": "Stealing the CA private key is the AD CS equivalent of krbtgt - extremely powerful and worth heavy detection investment by defenders.",
        "remediation": "Protect CA keys with an HSM, monitor CA host access, and rotate the CA key pair if compromise is suspected.",
        "references": (SOURCES["certified_preowned"],
                       "https://bloodhound.specterops.io/resources/edges/golden-cert"),
    },
    "Kerberoastable": {
        "opsec": "Request one TGS and crack offline; bulk SPN ticket requests (4769) from one host are a textbook Kerberoast signature.",
        "remediation": "Use gMSA, enforce AES, give SPN accounts 25+ char passwords, and alert on RC4 4769.",
        "references": ("https://adsecurity.org/?p=3458",
                       "https://www.thehacker.recipes/ad/movement/kerberos/kerberoast"),
    },
    "AdminTo": {
        "opsec": "PsExec-style exec drops a service (7045) and a type-3 logon (4624). Prefer WinRM/WMI with native tooling to blend in.",
        "remediation": "Roll local admin with LAPS, restrict lateral SMB/WinRM, and monitor 7045 service installs.",
        "references": (SOURCES["lolbas"], "https://attack.mitre.org/techniques/T1021/"),
    },
}


def _enrich_knowledge_base() -> None:
    """Attach references / opsec / remediation to every technique in place."""
    global UNKNOWN
    for kind, t in list(TECHNIQUES.items()):
        b = BESPOKE.get(kind, {})
        TECHNIQUES[kind] = replace(
            t,
            references=tuple(b.get("references") or CATEGORY_REFERENCES.get(t.category, ())),
            opsec=b.get("opsec") or CATEGORY_OPSEC.get(t.category, ""),
            remediation=b.get("remediation") or CATEGORY_REMEDIATION.get(t.category, ""),
        )
    UNKNOWN = replace(
        UNKNOWN,
        references=CATEGORY_REFERENCES["acl"],
        opsec="Unknown technique - treat as medium risk and investigate the edge before relying on it.",
        remediation="Identify the underlying right and apply least-privilege; classify it in techniques.py.",
    )


_enrich_knowledge_base()


# Precomputed lowercase index so the case-insensitive lookup below stays O(1)
# even though it runs once per edge for every pathfinding search.
# (Built AFTER enrichment so the index points at the enriched objects.)
_LOWER_INDEX: dict[str, Technique] = {k.lower(): v for k, v in TECHNIQUES.items()}


def get_technique(edge_kind: str) -> Technique:
    """Return the Technique for a BloodHound edge kind (or a safe default).

    Matching is case-insensitive so that variants like "adcsesc1" / "ADCSESC1"
    or "dcsync" / "DCSync" all resolve to the same Technique.

    Example:
        >>> get_technique("HasSession").mitre
        'T1003.001'
        >>> get_technique("adcsesc1").category
        'certificate'
    """
    tech = TECHNIQUES.get(edge_kind)
    if tech is not None:
        return tech
    return _LOWER_INDEX.get(edge_kind.lower(), UNKNOWN)
