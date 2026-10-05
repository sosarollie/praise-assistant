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

"""Remediation subpackage: walks scan findings and applies per-finding remediation via :func:`remediate`."""
from __future__ import annotations

from vvaharness.remediation_agent.discovery import (  # noqa: F401
    Layout,
    cvss_score_of,
    load_findings,
    locate_report,
    prepare_layout,
)
from vvaharness.remediation_agent.interactive import (  # noqa: F401
    decode_key,
    parse_selection,
    render_rows,
    run_interactive,
)
from vvaharness.remediation_agent.models import RemediationVerdict  # noqa: F401
from vvaharness.remediation_agent.options import (  # noqa: F401
    VALID_MODES,
    RemediateOptions,
    parse_options,
)
from vvaharness.remediation_agent.plugin_runner import apply_plugin  # noqa: F401
from vvaharness.remediation_agent.remediate import remediate  # noqa: F401
from vvaharness.remediation_agent.report_parser import (  # noqa: F401
    DONE_MARKER,
    REMEDIATION_DIR_NAME,
    SCAN_DIR_NAME,
    Finding,
    find_scan_dir,
    latest_report,
    mark_done,
    parse_findings,
)
from vvaharness.remediation_agent.runner import (  # noqa: F401
    model_banner,
    process_targets,
    remediate_one,
)
from vvaharness.remediation_agent.select import (  # noqa: F401
    band_score,
    cfg_top_n_findings,
    parse_top_arg,
    resolve_top,
    select_top_by_cvss,
    select_top_logged,
)



