# Tests for causely_notification.template (template-driven webhook)
import base64
import json
from unittest.mock import patch, MagicMock

import pytest

from causely_notification.template import (
    forward_to_template,
    _render,
    _template_context,
    DEFAULT_VARIABLE_START,
    DEFAULT_VARIABLE_END,
)


SAMPLE_PAYLOAD = {
    "name": "Malfunction",
    "type": "ProblemDetected",
    "severity": "High",
    "objectId": "rc-123",
    "entity": {"id": "e1", "name": "my-service", "type": "KubernetesService"},
    "slos": [
        {"slo_entity": {"name": "SLO-A"}, "status": "AT_RISK"},
        {"slo_entity": {"name": "SLO-B"}, "status": "HEALTHY"},
    ],
    "description": {"summary": "Something broke."},
}


class TestTemplateContext:
    def test_context_has_payload_and_top_level_keys(self):
        ctx = _template_context(SAMPLE_PAYLOAD)
        assert ctx["payload"] == SAMPLE_PAYLOAD
        assert ctx["name"] == "Malfunction"
        assert ctx["severity"] == "High"
        assert ctx["entity"]["name"] == "my-service"
        assert len(ctx["slos"]) == 2

    def test_context_includes_token_when_provided(self):
        ctx = _template_context(SAMPLE_PAYLOAD, token="my-secret")
        assert ctx["token"] == "my-secret"

    def test_context_token_empty_string_when_none(self):
        ctx = _template_context(SAMPLE_PAYLOAD, token=None)
        assert ctx["token"] == ""


class TestRender:
    def test_direct_field(self):
        out = _render("[[ name ]]", SAMPLE_PAYLOAD)
        assert out == "Malfunction"

    def test_nested_field(self):
        out = _render("[[ entity.name ]]", SAMPLE_PAYLOAD)
        assert out == "my-service"

    def test_tojson_filter(self):
        out = _render("[[ entity | tojson ]]", SAMPLE_PAYLOAD)
        assert json.loads(out) == SAMPLE_PAYLOAD["entity"]

    def test_list_from_slos(self):
        tpl = '[{% for s in slos %}"[[ s.slo_entity.name ]]"{% if not loop.last %}, {% endif %}{% endfor %}]'
        out = _render(tpl, SAMPLE_PAYLOAD)
        assert json.loads(out) == ["SLO-A", "SLO-B"]

    def test_custom_delimiters(self):
        out = _render("{{ name }}", SAMPLE_PAYLOAD, "{{", "}}")
        assert out == "Malfunction"

    def test_severity_mapping_via_jinja_map(self):
        """Template-only severity map: Causely values -> target priority (P1/P2/...)."""
        tpl = (
            '{% set priority = {"Critical":"P1","High":"P2","Medium":"P3","Low":"P4"} %}'
            '{"priority": "[[ priority.get(severity, \'P4\') ]]"}'
        )
        out = _render(tpl, {**SAMPLE_PAYLOAD, "severity": "High"})
        assert json.loads(out)["priority"] == "P2"
        out = _render(tpl, {**SAMPLE_PAYLOAD, "severity": "Critical"})
        assert json.loads(out)["priority"] == "P1"
        out = _render(tpl, {**SAMPLE_PAYLOAD, "severity": "Unknown"})
        assert json.loads(out)["priority"] == "P4"

    def test_b64encode_filter(self):
        out = _render("[[ token | b64encode ]]", SAMPLE_PAYLOAD, token="hello")
        assert out == base64.b64encode(b"hello").decode()


class TestForwardToTemplate:
    @patch("causely_notification.template.requests.request")
    def test_posts_rendered_body_and_content_type(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {
            "body": '{"title": "[[ name ]]", "priority": "[[ severity ]]"}',
            "content_type": "application/json",
        }
        resp = forward_to_template(
            SAMPLE_PAYLOAD,
            "https://api.example.com/alerts",
            None,
            config,
        )
        assert resp.status_code == 200
        assert mock_request.call_count == 1
        call = mock_request.call_args
        assert call[0][1] == "https://api.example.com/alerts"  # method, url
        assert call[1]["headers"]["Content-Type"] == "application/json"
        body = call[1]["data"]
        assert body == '{"title": "Malfunction", "priority": "High"}'

    @patch("causely_notification.template.requests.request")
    def test_includes_entity_via_tojson(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {"body": '{"entity": [[ entity | tojson ]]}'}
        resp = forward_to_template(
            SAMPLE_PAYLOAD,
            "https://api.example.com/alerts",
            None,
            config,
        )
        assert resp.status_code == 200
        body = mock_request.call_args[1]["data"]
        data = json.loads(body)
        assert data["entity"] == SAMPLE_PAYLOAD["entity"]

    @patch("causely_notification.template.requests.request")
    def test_sends_bearer_token_when_provided(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {"body": "[[ name ]]"}
        forward_to_template(
            SAMPLE_PAYLOAD,
            "https://api.example.com/alerts",
            "secret-token",
            config,
        )
        assert mock_request.call_args[1]["headers"]["Authorization"] == "Bearer secret-token"

    @patch("causely_notification.template.requests.request")
    def test_custom_delimiters(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {
            "body": "{{ name }}",
            "delimiters": ["{{", "}}"],
        }
        forward_to_template(
            SAMPLE_PAYLOAD,
            "https://api.example.com/alerts",
            None,
            config,
        )
        assert mock_request.call_args[1]["data"] == "Malfunction"

    def test_raises_when_body_missing(self):
        with pytest.raises(ValueError, match="template.body"):
            forward_to_template(
                SAMPLE_PAYLOAD,
                "https://api.example.com/alerts",
                None,
                {},
            )

    @patch("causely_notification.template.requests.request")
    def test_severity_mapping_in_body(self, mock_request):
        """Full template with priority map: severity High -> P2, default P4."""
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {
            "body": (
                '{% set priority = {"Critical":"P1","High":"P2","Medium":"P3","Low":"P4"} %}'
                '{"title": "[[ name ]]", "priority": "[[ priority.get(severity, \'P4\') ]]"}'
            ),
            "content_type": "application/json",
        }
        resp = forward_to_template(
            SAMPLE_PAYLOAD,
            "https://api.example.com/alerts",
            None,
            config,
        )
        assert resp.status_code == 200
        body = json.loads(mock_request.call_args[1]["data"])
        assert body["title"] == "Malfunction"
        assert body["priority"] == "P2"

    @patch("causely_notification.template.requests.request")
    def test_custom_headers_from_payload_and_token(self, mock_request):
        """Headers can use template values: payload fields and token (e.g. base64 for auth)."""
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {
            "body": "[[ name ]]",
            "headers": {
                "X-Request-Id": "[[ name ]]-[[ objectId ]]",
                "Authorization": "Basic [[ token | b64encode ]]",
            },
        }
        resp = forward_to_template(
            SAMPLE_PAYLOAD,
            "https://api.example.com/alerts",
            "my-token",
            config,
        )
        assert resp.status_code == 200
        headers = mock_request.call_args[1]["headers"]
        assert headers["X-Request-Id"] == "Malfunction-rc-123"
        assert headers["Authorization"] == "Basic " + base64.b64encode(b"my-token").decode()
        # Custom Authorization from template overrides default Bearer
        assert "Bearer" not in headers["Authorization"]

    @patch("causely_notification.template.requests.request")
    def test_configurable_http_method_default_post(self, mock_request):
        """Default method is POST."""
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {"body": "[[ name ]]"}
        forward_to_template(SAMPLE_PAYLOAD, "https://api.example.com/alerts", None, config)
        assert mock_request.call_args[0][0] == "POST"

    @patch("causely_notification.template.requests.request")
    def test_configurable_http_method_put(self, mock_request):
        """method can be PUT (or GET, PATCH, DELETE)."""
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        config = {"body": "[[ name ]]", "method": "PUT"}
        forward_to_template(SAMPLE_PAYLOAD, "https://api.example.com/alerts", None, config)
        assert mock_request.call_args[0][0] == "PUT"

    def test_invalid_http_method_raises(self):
        with pytest.raises(ValueError, match="template.method must be one of"):
            forward_to_template(
                SAMPLE_PAYLOAD,
                "https://api.example.com/alerts",
                None,
                {"body": "x", "method": "INVALID"},
            )

    @patch("causely_notification.template.requests.request")
    def test_holmesgpt_stream_investigate_example(self, mock_request):
        """Template maps Causely payload to HolmesGPT /api/investigate request shape."""
        mock_request.return_value = MagicMock(status_code=200, content=b"ok")
        # Request shape per https://holmesgpt.dev/reference/http-api/#request-fields_1
        config = {
            "content_type": "application/json",
            "body": """{
          "source": "causely",
          "title": "[[ name ]]",
          "description": "[[ description.summary | default('') ]]",
          "subject": [[ entity | tojson ]],
          "context": {
            "severity": "[[ severity ]]",
            "link": "[[ link | default('') ]]",
            "objectId": "[[ objectId | default('') ]]",
            "labels": [[ labels | default({}) | tojson ]]
          },
          "include_tool_calls": true
        }""",
        }
        payload = {
            **SAMPLE_PAYLOAD,
            "link": "https://causely.example/rootCauses/rc-123",
            "labels": {"k8s.namespace.name": "istio-system"},
        }
        resp = forward_to_template(
            payload,
            "https://holmes.example.com/api/investigate",
            None,
            config,
        )
        assert resp.status_code == 200
        assert mock_request.call_count == 1
        assert mock_request.call_args[0][0] == "POST"
        assert mock_request.call_args[0][1] == "https://holmes.example.com/api/investigate"
        body = json.loads(mock_request.call_args[1]["data"])
        assert body["source"] == "causely"
        assert body["title"] == "Malfunction"
        assert body["description"] == "Something broke."
        assert body["subject"] == payload["entity"]
        assert body["context"]["severity"] == "High"
        assert body["context"]["link"] == "https://causely.example/rootCauses/rc-123"
        assert body["context"]["objectId"] == "rc-123"
        assert body["context"]["labels"] == {"k8s.namespace.name": "istio-system"}
        assert body["include_tool_calls"] is True
