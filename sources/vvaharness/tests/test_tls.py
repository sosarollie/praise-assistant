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

"""Unit tests for vvaharness.backends._tls.coerce_verify.

Pure function — no network, no SDK, deterministic.
"""
import pytest

from vvaharness.backends.llm.tls import coerce_verify


@pytest.mark.parametrize("value", ["false", "FALSE", "False", "0", "no", "off", " off "])
def test_string_falsey_coerces_to_bool_false(value):
    assert coerce_verify(value) is False


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on", " on "])
def test_string_truthy_coerces_to_bool_true(value):
    assert coerce_verify(value) is True


def test_real_bools_pass_through():
    assert coerce_verify(True) is True
    assert coerce_verify(False) is False


def test_none_passes_through():
    assert coerce_verify(None) is None


@pytest.mark.parametrize("path", [
    "/etc/ssl/certs/ca-bundle.pem",
    "C:\\certs\\ca.pem",
    "relative/ca.crt",
])
def test_ca_bundle_path_string_untouched(path):
    # A non-boolean string is a CA-bundle path and must be returned unchanged.
    assert coerce_verify(path) == path
