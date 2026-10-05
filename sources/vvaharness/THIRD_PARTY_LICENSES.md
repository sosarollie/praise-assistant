<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# Third-Party License Inventory

vvaharness is licensed under Apache-2.0 (see `LICENSE`). It depends on the
third-party packages listed below. These dependencies are installed from PyPI
at install time (`pipx install .` / `pip install .`) and are **not** vendored
or redistributed as part of this repository. This inventory is provided for
transparency and compliance review.

**Source:** the CycloneDX 1.6 SBOM generated on 2026-09-10. The snapshot
contains **86 unique third-party packages**, counting each package/version
once across source archives and platform-specific distributions: the 18 direct
runtime dependencies listed below, plus 68 additional packages, including
transitive dependencies and development tools. The table lists the direct
dependencies with their existing version constraints, XML snapshot versions,
and licence identifiers recorded in the SBOM.

### Direct runtime dependencies

| Package | Version  | License |
|---|---|---|---|
| pydantic | >=2.13.5,<3  | MIT |
| pydantic-settings | >=2.15.0,<3  | MIT |
| PyYAML | >=6.0.3,<7  |  MIT |
| anthropic | >=0.125.0,<1.0 |  MIT |
| openai | >=3.7.0,<4 |  Apache-2.0 |
| httpx | >=0.28.1,<1 |  BSD-3-Clause |
| httpx2 | >=2.12.0,<3 |  BSD-3-Clause |
| urllib3 | >=2.7.0,<3 |  MIT |
| python-dotenv | >=1.2.3,<2 |  BSD-3-Clause |
| typing_extensions | >=4.16.0,<5 |  PSF-2.0 |
| claude-agent-sdk | >=0.2.151,<0.3 |  MIT |
| tree-sitter | >=0.26.0,<0.27 |  MIT |
| tree-sitter-language-pack | >=1.16.1,<2 |  MIT |
| deepagents | >=0.7.13,<0.8 |  MIT |
| langchain | >=1.3.18,<2 |  MIT |
| langchain-anthropic | >=1.7.0,<2 |  MIT |
| langchain-openai | >=1.6.0,<2 |  MIT |
| langgraph | >=1.2.11,<2 |  MIT |

The remaining 68 packages include transitive dependencies and development tools
(e.g. `anyio`, `annotated-types`, `h11`, `httpcore`, `idna`, `sniffio`,
`distro`, `pydantic-core`, `packaging`, `requests`, `starlette`, and
`websockets`). Recorded licence identifiers are mostly permissive — MIT,
MIT-0, BSD-2-Clause, BSD-3-Clause, Apache-2.0, PSF-2.0 or CNRI-Python;
`certifi` and `orjson` include MPL-2.0 terms (weak-copyleft at the file level).
The snapshot also contains non-specific licence labels (`BSD` and
`Not Supported`), so licence compatibility requires review of the applicable
upstream terms.
