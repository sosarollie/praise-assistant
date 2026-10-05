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
# GitHub Copilot instructions

This repo is **vvaharness**, a released CLI security-scanning product. The full
agent operating manual is in `AGENTS.md` at the repo root — follow it.

Do NOT modify the `vvaharness/` package or hand-write config files to make a
scan run. If a command fails, run `vvaharness setup` / `vvaharness doctor`,
fix the environment (usually a missing credential or the `ANTHROPIC_BASE_URL`
gateway), then re-run. Report genuine bugs instead of patching the source.

Detection-only: `pipx install .` → `vvaharness setup` →
`vvaharness scan --repo <path> --stop-after s9`.

The packaged default sets `step_remediate.enabled: false` and
`step_validate.enabled: false`, so a plain scan using it skips S10/S11.
Other configs or a local overlay can enable them (`sdk`/`full` still do).
`--remediate` enables S10 only and can edit target source; in-scan S11 requires
its own config opt-in. Standalone `remediate` and `validate` remain available.
Keep `--stop-after s9` to explicitly skip both stages with any profile.

- **Beta — API only.** Exploit verification needs a Postman/OpenAPI/Swagger
  collection and can only verify findings that map to an HTTP endpoint;
  everything else stays SAST-only. It is localhost-only, sends live attack
  traffic, and is off unless `EV_API_COLLECTION` is set.
