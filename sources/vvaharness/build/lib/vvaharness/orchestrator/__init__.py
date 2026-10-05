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

"""Agentic SAST — profile-controlled S0 static seeding plus an S1-S11 workflow (detection, remediation, then validation), run via ``vvaharness scan --repo <path>``."""
import shutil as shutil  # re-exported: patched by tests via orchestrator.shutil

from vvaharness.orchestrator.batch import run_batch as run_batch
from vvaharness.orchestrator.checkpoints import (
    load_ckpt as load_ckpt,
)
from vvaharness.orchestrator.checkpoints import (
    run_id_for as run_id_for,
)
from vvaharness.orchestrator.checkpoints import (
    save_ckpt as save_ckpt,
)
from vvaharness.orchestrator.cleanup import (
    _preserve_set as _preserve_set,
)
from vvaharness.orchestrator.cleanup import (
    _purge_clone as _purge_clone,
)
from vvaharness.orchestrator.cleanup import (
    _rmtree_rw as _rmtree_rw,
)
from vvaharness.orchestrator.cmdb import (
    _cmdb_path as _cmdb_path,
)
from vvaharness.orchestrator.cmdb import (
    _load_app_profile as _load_app_profile,
)
from vvaharness.orchestrator.cmdb import (
    _set_cmdb_path as _set_cmdb_path,
)
from vvaharness.orchestrator.config_paths import (
    _MODEL_ROLES as _MODEL_ROLES,
)
from vvaharness.orchestrator.config_paths import (
    _app_root as _app_root,
)
from vvaharness.orchestrator.config_paths import (
    _default_config as _default_config,
)
from vvaharness.orchestrator.config_paths import (
    _iter_model_roles as _iter_model_roles,
)
from vvaharness.orchestrator.config_paths import (
    _resolve_against as _resolve_against,
)
from vvaharness.orchestrator.enrich_findings import _enrich_findings as _enrich_findings
from vvaharness.orchestrator.entry import main as main
from vvaharness.orchestrator.preflight import (
    _mask as _mask,
)
from vvaharness.orchestrator.preflight import (
    _reachable_despite_token_cap as _reachable_despite_token_cap,
    _reachable_despite_truncated_reply as _reachable_despite_truncated_reply,
)
from vvaharness.orchestrator.preflight import (
    check_backends as check_backends,
)
from vvaharness.orchestrator.preflight import (
    configure_backends as configure_backends,
)
from vvaharness.orchestrator.preflight import (
    probe_backends as probe_backends,
)
from vvaharness.orchestrator.scan import scan_repo as scan_repo
