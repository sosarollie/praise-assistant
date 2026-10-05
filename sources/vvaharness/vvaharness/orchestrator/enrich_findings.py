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


from __future__ import annotations

"""orchestrator.enrich_findings — see package docstring."""
from vvaharness.report import enrich as vcs_enrich


def _prefix_path(path: str | None, prefix: str) -> str | None:
    if not path or path.startswith(f"{prefix}/"):
        return path
    return f"{prefix}/{path}"


def _prefix_ref(ref: str | None, prefix: str) -> str | None:
    # source_ref / sink_ref are "file:line" — prefix only the file part.
    if not ref:
        return ref
    file_part, sep, line_part = ref.partition(":")
    return f"{_prefix_path(file_part, prefix)}{sep}{line_part}"


def _enrich_findings(findings: list, app_info,
                     path_prefix: str | None = None) -> None:
    """Post-s7: attach VulContextSeverity env score + OffensivePriority to each verified
    Finding so s8 can render them natively in the MD. When path_prefix is
    given (per-repo batch mode), prepend it to file/source_ref/sink_ref so
    MD + SARIF locations match the --group-by-app layout."""
    for f in findings:
        if path_prefix:
            f.file = _prefix_path(f.file, path_prefix)
            f.source_ref = _prefix_ref(getattr(f, "source_ref", None),
                                       path_prefix)
            f.sink_ref = _prefix_ref(getattr(f, "sink_ref", None),
                                     path_prefix)
        if f.cvss_vector and app_info is not None:
            vr = vcs_enrich.vsvs_score(f.cvss_vector, app_info)
            if vr:
                f.vsvs_vector = vr.vector
                f.vsvs_score = vr.score
                f.vsvs_rating = vr.rating
        f.offensive_priority, f.offensive_reason = vcs_enrich.offensive_priority_for(
            f.title, f.vuln_class.value, f.description, f.cvss_vector, app_info)
