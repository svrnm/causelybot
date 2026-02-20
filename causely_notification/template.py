# Copyright 2025 Causely, Inc.
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
#
# SPDX-License-Identifier: Apache-2.0

"""
Template-driven webhook: map Causely payloads to any backend via Jinja2.

Use this when you want to drive the outgoing request body (and optionally headers)
from configuration instead of a dedicated backend module. The template receives
the full Causely payload and can:
- Point exactly to fields (e.g. severity -> priority)
- Transform structures (e.g. slos -> list of names)
- Include parts of the payload (e.g. entity as JSON)
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any, Dict, Optional

import requests
from jinja2 import Environment, BaseLoader, select_autoescape
from markupsafe import Markup


# Default delimiters [[ ]] avoid clashes with Helm/Go templates when template
# body is in values.yaml; use delimiters: ["{{", "}}"] for standard Jinja2.
DEFAULT_VARIABLE_START = "[["
DEFAULT_VARIABLE_END = "]]"

ALLOWED_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


def _make_env(
    variable_start_string: str = DEFAULT_VARIABLE_START,
    variable_end_string: str = DEFAULT_VARIABLE_END,
) -> Environment:
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(default=False),
        variable_start_string=variable_start_string,
        variable_end_string=variable_end_string,
    )

    def tojson(obj: Any) -> Markup:
        """Serialize a value to JSON (e.g. include entity or slos in payload). Safe so quotes are not escaped."""
        return Markup(json.dumps(obj))

    def b64encode(s: Any) -> str:
        """Base64-encode a string (e.g. token for Basic/Bearer auth in headers)."""
        if s is None:
            return ""
        return base64.b64encode(str(s).encode()).decode()

    env.filters["tojson"] = tojson
    env.filters["b64encode"] = b64encode
    return env


def _template_context(
    payload: Dict[str, Any],
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Build Jinja2 context: full payload, top-level keys, and webhook token."""
    ctx = {"payload": payload, "token": token or ""}
    for key, value in payload.items():
        ctx[key] = value
    return ctx


def _render(
    template_str: str,
    payload: Dict[str, Any],
    variable_start: str = DEFAULT_VARIABLE_START,
    variable_end: str = DEFAULT_VARIABLE_END,
    token: Optional[str] = None,
) -> str:
    env = _make_env(variable_start, variable_end)
    tpl = env.from_string(template_str)
    return tpl.render(**_template_context(payload, token)).strip()


def _render_headers(
    headers_config: Optional[Dict[str, str]],
    payload: Dict[str, Any],
    variable_start: str,
    variable_end: str,
    token: Optional[str] = None,
) -> Dict[str, str]:
    if not headers_config:
        return {}
    out = {}
    for k, v in headers_config.items():
        if isinstance(v, str) and (variable_start in v or variable_end in v):
            out[k] = _render(v, payload, variable_start, variable_end, token)
        else:
            out[k] = str(v)
    return out


def forward_to_template(
    payload: Dict[str, Any],
    url: str,
    token: Optional[str],
    template_config: Dict[str, Any],
) -> requests.Response:
    """
    Render the request body (and optional headers) from a Jinja2 template and POST to url.

    template_config may contain:
    - body (str, required): Jinja2 template for the request body.
    - method (str, optional): HTTP method (default: POST). One of GET, POST, PUT, PATCH, DELETE.
    - content_type (str, optional): Content-Type header (default: application/json).
    - headers (dict, optional): Extra headers; values can be templates.
    - delimiters (list, optional): [start, end] e.g. ["[[", "]]"] (default) or ["{{", "}}"].

    The template context includes the full Causely payload as `payload`, each
    top-level key (name, severity, entity, slos, etc.), and `token` (the webhook
    token, for use in headers e.g. Bearer or Basic). Use the `tojson` filter to
    embed JSON; use the `b64encode` filter to base64-encode the token for custom auth.
    """
    body_tpl = template_config.get("body")
    if not body_tpl:
        raise ValueError("template webhook requires template.body")

    delimiters = template_config.get("delimiters") or [DEFAULT_VARIABLE_START, DEFAULT_VARIABLE_END]
    if len(delimiters) != 2:
        raise ValueError("template.delimiters must be a list [start_string, end_string]")
    var_start, var_end = delimiters[0], delimiters[1]

    body = _render(body_tpl, payload, var_start, var_end, token)
    content_type = template_config.get("content_type", "application/json")
    headers = {"Content-Type": content_type}
    headers.update(
        _render_headers(
            template_config.get("headers"),
            payload,
            var_start,
            var_end,
            token,
        )
    )
    # Default Bearer only if token set and template did not set Authorization
    if token and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {token}"

    method = (template_config.get("method") or "POST").strip().upper()
    if method not in ALLOWED_HTTP_METHODS:
        raise ValueError(
            f"template.method must be one of {sorted(ALLOWED_HTTP_METHODS)}, got {method!r}"
        )

    if len(body) > 500:
        print(f"Template webhook body (preview): {body[:500]}...", file=sys.stderr)
    else:
        print(f"Template webhook body: {body}", file=sys.stderr)
    return requests.request(
        method, url, data=body, headers=headers, timeout=30
    )
