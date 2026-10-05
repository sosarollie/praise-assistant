# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
CWE id → canonical MITRE name. Single source of truth for MD rendering,
SARIF emission, and the backfill tool. Unknown ids resolve to "" so callers
can safely fall back to the bare id.
"""
from __future__ import annotations

CWE_NAMES: dict[str, str] = {
    "CWE-20":   "Improper Input Validation",
    "CWE-22":   "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-73":   "External Control of File Name or Path",
    "CWE-74":   "Improper Neutralization of Special Elements in Output (Injection)",
    "CWE-77":   "Improper Neutralization of Special Elements used in a Command (Command Injection)",
    "CWE-78":   "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
    "CWE-79":   "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "CWE-89":   "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    "CWE-90":   "Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)",
    "CWE-94":   "Improper Control of Generation of Code (Code Injection)",
    "CWE-95":   "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
    "CWE-119":  "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120":  "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
    "CWE-121":  "Stack-based Buffer Overflow",
    "CWE-122":  "Heap-based Buffer Overflow",
    "CWE-125":  "Out-of-bounds Read",
    "CWE-134":  "Use of Externally-Controlled Format String",
    "CWE-190":  "Integer Overflow or Wraparound",
    "CWE-200":  "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-209":  "Generation of Error Message Containing Sensitive Information",
    "CWE-269":  "Improper Privilege Management",
    "CWE-276":  "Incorrect Default Permissions",
    "CWE-284":  "Improper Access Control",
    "CWE-285":  "Improper Authorization",
    "CWE-287":  "Improper Authentication",
    "CWE-294":  "Authentication Bypass by Capture-replay",
    "CWE-295":  "Improper Certificate Validation",
    "CWE-306":  "Missing Authentication for Critical Function",
    "CWE-311":  "Missing Encryption of Sensitive Data",
    "CWE-312":  "Cleartext Storage of Sensitive Information",
    "CWE-319":  "Cleartext Transmission of Sensitive Information",
    "CWE-326":  "Inadequate Encryption Strength",
    "CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330":  "Use of Insufficiently Random Values",
    "CWE-345":  "Insufficient Verification of Data Authenticity",
    "CWE-347":  "Improper Verification of Cryptographic Signature",
    "CWE-352":  "Cross-Site Request Forgery (CSRF)",
    "CWE-362":  "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
    "CWE-367":  "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-384":  "Session Fixation",
    "CWE-400":  "Uncontrolled Resource Consumption",
    "CWE-416":  "Use After Free",
    "CWE-426":  "Untrusted Search Path",
    "CWE-434":  "Unrestricted Upload of File with Dangerous Type",
    "CWE-444":  "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)",
    "CWE-476":  "NULL Pointer Dereference",
    "CWE-489":  "Active Debug Code",
    "CWE-502":  "Deserialization of Untrusted Data",
    "CWE-522":  "Insufficiently Protected Credentials",
    "CWE-532":  "Insertion of Sensitive Information into Log File",
    "CWE-552":  "Files or Directories Accessible to External Parties",
    "CWE-601":  "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611":  "Improper Restriction of XML External Entity Reference",
    "CWE-639":  "Authorization Bypass Through User-Controlled Key",
    "CWE-640":  "Weak Password Recovery Mechanism for Forgotten Password",
    "CWE-643":  "Improper Neutralization of Data within XPath Expressions (XPath Injection)",
    "CWE-668":  "Exposure of Resource to Wrong Sphere",
    "CWE-693":  "Protection Mechanism Failure",
    "CWE-732":  "Incorrect Permission Assignment for Critical Resource",
    "CWE-770":  "Allocation of Resources Without Limits or Throttling",
    "CWE-787":  "Out-of-bounds Write",
    "CWE-798":  "Use of Hard-coded Credentials",
    "CWE-829":  "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-840":  "Business Logic Errors",
    "CWE-841":  "Improper Enforcement of Behavioral Workflow",
    "CWE-843":  "Access of Resource Using Incompatible Type (Type Confusion)",
    "CWE-862":  "Missing Authorization",
    "CWE-863":  "Incorrect Authorization",
    "CWE-915":  "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918":  "Server-Side Request Forgery (SSRF)",
    "CWE-923":  "Improper Restriction of Communication Channel to Intended Endpoints",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1188": "Initialization of a Resource with an Insecure Default",
    "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
    "CWE-1333": "Inefficient Regular Expression Complexity",
    "CWE-1390": "Weak Authentication",
}


def cwe_name(cwe_id: str | None) -> str:
    """Return the MITRE name for 'CWE-NNN', or '' if unknown/None."""
    if not cwe_id:
        return ""
    return CWE_NAMES.get(cwe_id.upper().strip(), "")


# B1: VulnClass → canonical CWE fallback. Many s4 findings carry only
# `vuln_class`; this map lets `cwe_for` resolve a CWE deterministically when
# `Finding.cwe` is None — without changing the s4 prompt or trusting an
# LLM-emitted CWE.
VULNCLASS_CWE: dict[str, str] = {
    "use-after-free":         "CWE-416",
    "heap-overflow":          "CWE-122",
    "stack-overflow":         "CWE-121",
    "format-string":          "CWE-134",
    "integer-overflow":       "CWE-190",
    "type-confusion":         "CWE-843",
    "race-condition":         "CWE-362",
    "injection":              "CWE-74",     # generic injection parent
    "unsafe-deserialization": "CWE-502",
    "logic-flaw":             "CWE-840",
    "info-leak":              "CWE-200",
    "other":                  "",           # unresolved → no CWE
}


def cwe_for(cwe_id: str | None, vuln_class) -> str | None:
    """Return `cwe_id` if set, else the VulnClass fallback, else None.
    `vuln_class` may be a VulnClass enum or its `.value` string."""
    if cwe_id:
        return cwe_id.upper().strip()
    key = getattr(vuln_class, "value", None) or str(vuln_class or "")
    fb = VULNCLASS_CWE.get(key, "")
    return fb or None


def cwe_label(cwe_id: str | None) -> str:
    """'CWE-862 - Missing Authorization' or just 'CWE-862' if name unknown."""
    if not cwe_id:
        return ""
    name = cwe_name(cwe_id)
    return f"{cwe_id} - {name}" if name else cwe_id
