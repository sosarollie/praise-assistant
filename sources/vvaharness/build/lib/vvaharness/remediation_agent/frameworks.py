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

"""remediation_agent.frameworks — per-file language + per-repo framework detection.

The playbook resolves a fix strategy on (CWE, language, framework). The language
must come from the *finding's file extension* (a repo's primary language is wrong
for polyglot repos), and frameworks are inferred once per repo from manifest
files. Both are cheap, deterministic, and dependency-light."""
from __future__ import annotations

from pathlib import Path

# Extension → playbook language key (the playbook's coarser keys: no separate
# ts/js; kotlin/scala/groovy fold into java for strategy purposes).
_EXT_LANG: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".java": "java", ".kt": "java", ".scala": "java", ".groovy": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
}

# Manifest file → marker substrings → framework key (matches playbook keys).
_MANIFESTS: dict[str, dict[str, str]] = {
    "requirements.txt": {
        "django": "django", "flask": "flask", "sqlalchemy": "sqlalchemy",
        "fastapi": "fastapi",
    },
    "pyproject.toml": {
        "django": "django", "flask": "flask", "sqlalchemy": "sqlalchemy",
        "fastapi": "fastapi",
    },
    "Pipfile": {
        "django": "django", "flask": "flask", "sqlalchemy": "sqlalchemy",
    },
    "package.json": {
        '"react"': "react", '"next"': "react",
        '"express"': "express", '"vue"': "vue", '"angular"': "angular",
    },
    "pom.xml": {
        "spring-boot": "spring", "<groupId>org.springframework": "spring",
        "hibernate": "hibernate",
    },
    "build.gradle": {
        "org.springframework": "spring", "spring-boot": "spring",
    },
    "Gemfile": {"rails": "rails", "sinatra": "sinatra"},
    "go.mod": {"gin-gonic": "gin", "gorilla/mux": "gorilla"},
}


def language_for(file_path: str) -> str:
    """Playbook language key for *file_path*, or ``"default"`` if unknown."""
    return _EXT_LANG.get(Path(file_path or "").suffix.lower(), "default")


def detect_frameworks(repo_root: str | Path) -> set[str]:
    """Cheap manifest grep over the repo root and its immediate children. The
    caller should cache the result for the run (it never changes mid-run)."""
    root = Path(repo_root)
    found: set[str] = set()
    for fname, markers in _MANIFESTS.items():
        for p in list(root.glob(fname)) + list(root.glob(f"*/{fname}")):
            try:
                txt = p.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue
            for needle, fw in markers.items():
                if needle.lower() in txt:
                    found.add(fw)
    return found
