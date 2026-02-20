# Tests for causely_notification.server (webhook routing, filters, payload forwarding)
import os
import textwrap

import pytest
import yaml
from unittest.mock import patch, Mock, MagicMock

# Set env vars before importing server (server uses them for URL lookup)
os.environ["AUTH_TOKEN"] = "test-token"

# Single-webhook-per-backend for parameterized tests (name "slack-test" -> URL_SLACK-TEST)
os.environ["URL_SLACK-TEST"] = "http://test_slack"
os.environ["URL_TEAMS-TEST"] = "http://test_teams"
os.environ["URL_JIRA-TEST"] = "http://test_jira"
os.environ["URL_OPSGENIE-TEST"] = "http://test_opsgenie"
os.environ["URL_GITHUB-TEST"] = "test_owner/test_repo"
os.environ["URL_TEMPLATE-TEST"] = "http://test_template"

# Multi-webhook config (existing slack-only) for filter/scenario tests
os.environ["URL_SLACK-SEVERITY"] = "http://test_slack"
os.environ["URL_SLACK-MALFUNCTION-SLO"] = "http://test_slack"
os.environ["URL_SLACK-ALL-ALERTS"] = "http://test_slack"

from causely_notification import server
from causely_notification.server import app, populate_webhooks

BACKENDS = ["slack", "teams", "jira", "opsgenie", "github"]

# Expected success status per backend (server accepts 200, 201, 202)
BACKEND_SUCCESS_STATUS = {
    "slack": 200,
    "teams": 200,
    "jira": 201,
    "opsgenie": 202,
    "github": 201,
}

def _expected_url(hook_type: str) -> str:
    # Webhook name is "{hook_type}-test" -> normalized URL_{HOOK_TYPE}-TEST
    key = f"URL_{hook_type.upper()}-TEST"
    base = os.environ.get(key)
    if not base:
        base = f"http://test_{hook_type}"
    if hook_type == "jira":
        return f"{base}/rest/api/2/issue"
    if hook_type == "github":
        return f"https://api.github.com/repos/{base}/issues"
    return base


def _one_webhook_config(hook_type: str, filters_enabled: bool = False, filter_values=None):
    name = f"{hook_type}-test"
    filter_values = filter_values or []
    lines = [
        "webhooks:",
        f'  - name: "{name}"',
        f'    hook_type: "{hook_type}"',
        f'    url: "https://example.com/{hook_type}"',
    ]
    if hook_type in ("slack", "jira", "opsgenie", "github"):
        lines.append('    token: "fake-token"')
    if filters_enabled and filter_values:
        lines.append("    filters:")
        lines.append("      enabled: true")
        lines.append("      values:")
        for v in filter_values:
            lines.append(f'        - field: "{v["field"]}"')
            lines.append(f'          operator: "{v["operator"]}"')
            lines.append(f'          value: {v["value"]}')
    else:
        lines.append("    filters:")
        lines.append("      enabled: false")
    return "\n".join(lines)


test_payload = {
    "link": "https://portal.staging.causely.app/rootCauses/d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "name": "Malfunction",
    "type": "ProblemDetected",
    "entity": {
        "id": "ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "link": "https://portal.staging.causely.app/observe/topology/ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "name": "/webhook/teams",
        "type": "HTTPPath"
    },
    "labels": {
        "causely.ai/service-id": "fdea69a6-7ae3-504c-a5f9-cd450d135672",
        "causely.ai/service-name": "causelybot"
    },
    "objectId": "d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "severity": "High",
    "timestamp": "2025-08-07T18:51:54.164185287Z",
    "description": {
        "details": "A higher error rate can stem from multiple factors...",
        "summary": "The HTTP path is experiencing a high rate of errors...",
        "remediationOptions": [
            {"title": "Check Logs", "description": "Inspect the application logs..."}
        ]
    }
}

test_payload_update = {
    "link": "https://portal.staging.causely.app/rootCauses/d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "name": "Malfunction",
    "type": "ProblemUpdated",
    "entity": {
        "id": "ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "link": "https://portal.staging.causely.app/observe/topology/ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "name": "/webhook/teams",
        "type": "HTTPPath"
    },
    "labels": {
        "causely.ai/service-id": "fdea69a6-7ae3-504c-a5f9-cd450d135672",
        "causely.ai/service-name": "causelybot"
    },
    "objectId": "d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "severity": "High",
    "old_severity": "Low",
    "timestamp": "2025-08-07T18:51:54.164185287Z",
    "description": {
        "details": "A higher error rate can stem from multiple factors...",
        "summary": "The HTTP path is experiencing a high rate of errors...",
        "remediationOptions": [
            {"title": "Check Logs", "description": "Inspect the application logs..."}
        ]
    }
}

test_payload_update_lower = {
    "link": "https://portal.staging.causely.app/rootCauses/d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "name": "Malfunction",
    "type": "ProblemUpdated",
    "entity": {
        "id": "ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "link": "https://portal.staging.causely.app/observe/topology/ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "name": "/webhook/teams",
        "type": "HTTPPath"
    },
    "labels": {
        "causely.ai/service-id": "fdea69a6-7ae3-504c-a5f9-cd450d135672",
        "causely.ai/service-name": "causelybot"
    },
    "objectId": "d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "severity": "Low",
    "old_severity": "High",
    "timestamp": "2025-08-07T18:51:54.164185287Z",
    "description": {
        "details": "A higher error rate can stem from multiple factors...",
        "summary": "The HTTP path is experiencing a high rate of errors...",
        "remediationOptions": [
            {"title": "Check Logs", "description": "Inspect the application logs..."}
        ]
    }
}

test_payload_update_same = {
    "link": "https://portal.staging.causely.app/rootCauses/d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "name": "Malfunction",
    "type": "ProblemUpdated",
    "entity": {
        "id": "ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "link": "https://portal.staging.causely.app/observe/topology/ac462ed5-87cb-5a1a-9586-b2951b52adda",
        "name": "/webhook/teams",
        "type": "HTTPPath"
    },
    "labels": {
        "causely.ai/service-id": "fdea69a6-7ae3-504c-a5f9-cd450d135672",
        "causely.ai/service-name": "causelybot"
    },
    "objectId": "d76f027d-e697-46ed-8a2c-f16356a97ceb",
    "severity": "High",
    "old_severity": "High",
    "timestamp": "2025-08-07T18:51:54.164185287Z",
    "description": {
        "details": "A higher error rate can stem from multiple factors...",
        "summary": "The HTTP path is experiencing a high rate of errors...",
        "remediationOptions": [
            {"title": "Check Logs", "description": "Inspect the application logs..."}
        ]
    }
}

test_payload_for_filters = {
    "link": "https://portal.causely.app",
    "name": "Causely: Test Notification 20",
    "type": "ProblemCleared",
    "entity": {
        "id": "2c990ff-7c5c-5a4f-a004-f6a1a9a58b85",
        "link": "https://portal.causely.app",
        "name": "the-most-important-service",
        "type": "Node"
    },
    "labels": {
        "k8s.cluster.name": "my-important-services-cluster",
        "gcp.resource.zone": "https://www.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a",
        "causely.ai/cluster": "production"
    },
    "objectId": "2ac21477-61f3-4ae0-9fc4-0c1ea43ff727",
    "severity": "Critical",
    "timestamp": "2025-06-27T19:15:16.410543344Z",
    "description": {
        "details": "UI Test Notification",
        "summary": "UI Test Notification."
    }
}

yaml_text = textwrap.dedent("""
webhooks:
  - name: "slack-severity"
    url: "https://hooks.slack.com/services/T00000000/B00000001/XXXXXXXXXXXXXXXXXXXXXXXX"
    token: ""
    hook_type: slack
    filters:
      enabled: true
      values:
        - field: "severity"
          operator: "in"
          value: ["High", "Critical"]
  - name: "slack-malfunction-slo"
    url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    token: ""
    hook_type: slack
    filters:
      enabled: true
      values:
        - field: "name"
          operator: "equals"
          value: "Malfunction"
        - field: "impactsSLO"
          operator: "equals"
          value: true
""")

config_test_yaml = textwrap.dedent("""
webhooks:
  - name: "slack-all-alerts"
    hook_type: "slack"
    url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    filters:
      enabled: true
      values:
        - field: "labels.k8s.cluster.name"
          operator: "in"
          value: ["my-important-services-cluster"]
""")


def _setup_webhooks(yaml_str: str):
    data = yaml.safe_load(yaml_str)
    webhooks = data.get("webhooks", data) if isinstance(data, dict) else data
    if not isinstance(webhooks, list):
        webhooks = [webhooks]
    filter_store, webhook_lookup_map = populate_webhooks(webhooks)
    server.filter_store = filter_store
    server.webhook_lookup_map = webhook_lookup_map


@patch("requests.request")
@patch("requests.post")
@pytest.mark.parametrize("hook_type", BACKENDS)
def test_webhook_posts_expected_payload(mock_post, mock_request, hook_type):
    """POST with ProblemDetected forwards to the configured backend (any type)."""
    if hook_type == "github":
        # github_request returns resp.json() if resp.content else None — need truthy content
        mock_request.side_effect = [
            MagicMock(ok=True, status_code=200, content=b"[]", json=lambda: []),
            MagicMock(
                ok=True,
                status_code=201,
                content=b" ",
                json=lambda: {"number": 1, "html_url": "https://github.com/test_owner/test_repo/issues/1"},
            ),
        ]
    else:
        mock_request.return_value = MagicMock(ok=True, status_code=200)
    mock_post.return_value = Mock(status_code=BACKEND_SUCCESS_STATUS[hook_type], content=b"ok")
    yaml_str = _one_webhook_config(hook_type, filters_enabled=False)
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post("/webhook", json=test_payload, headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    if hook_type == "github":
        assert mock_request.call_count >= 2
        assert mock_request.call_args_list[1].args[1] == _expected_url(hook_type)
    else:
        assert mock_post.call_count == 1
        assert mock_post.call_args_list[0].args[0] == _expected_url(hook_type)


@patch("requests.request")
@patch("requests.post")
@pytest.mark.parametrize("hook_type", BACKENDS)
def test_webhook_posts_expected_payload2(mock_post, mock_request, hook_type):
    """ProblemUpdated (severity went up): only webhooks that newly match are notified."""
    if hook_type == "github":
        mock_request.side_effect = [
            MagicMock(ok=True, status_code=200, content=b"[]", json=lambda: []),
            MagicMock(
                ok=True,
                status_code=201,
                content=b" ",
                json=lambda: {"number": 1, "html_url": "https://github.com/test_owner/test_repo/issues/1"},
            ),
        ]
    else:
        mock_request.return_value = MagicMock(ok=True, status_code=200)
    mock_post.return_value = Mock(status_code=BACKEND_SUCCESS_STATUS[hook_type], content=b"ok")
    # Filter: severity in [High, Critical]. Old payload has Low, new has High -> only new matches -> 1 forward
    yaml_str = _one_webhook_config(
        hook_type,
        filters_enabled=True,
        filter_values=[{"field": "severity", "operator": "in", "value": ["High", "Critical"]}],
    )
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload_update, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    if hook_type == "github":
        assert mock_request.call_count >= 2
        assert mock_request.call_args_list[1].args[1] == _expected_url(hook_type)
    else:
        assert mock_post.call_count == 1
        assert mock_post.call_args_list[0].args[0] == _expected_url(hook_type)


@patch("requests.request")
@patch("requests.post")
@pytest.mark.parametrize("hook_type", BACKENDS)
def test_webhook_posts_expected_payload3(mock_post, mock_request, hook_type):
    """ProblemUpdated (severity went down): only webhooks that newly match are notified."""
    if hook_type == "github":
        mock_request.side_effect = [
            MagicMock(ok=True, status_code=200, content=b"[]", json=lambda: []),
            MagicMock(
                ok=True,
                status_code=201,
                content=b" ",
                json=lambda: {"number": 1, "html_url": "https://github.com/test_owner/test_repo/issues/1"},
            ),
        ]
    else:
        mock_request.return_value = MagicMock(ok=True, status_code=200)
    mock_post.return_value = Mock(status_code=BACKEND_SUCCESS_STATUS[hook_type], content=b"ok")
    # Filter: severity in [Low]. Old payload has High, new has Low -> only new matches -> 1 forward
    yaml_str = _one_webhook_config(
        hook_type,
        filters_enabled=True,
        filter_values=[{"field": "severity", "operator": "in", "value": ["Low"]}],
    )
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload_update_lower, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    if hook_type == "github":
        assert mock_request.call_count >= 2
        assert mock_request.call_args_list[1].args[1] == _expected_url(hook_type)
    else:
        assert mock_post.call_count == 1
        assert mock_post.call_args_list[0].args[0] == _expected_url(hook_type)


@patch("requests.request")
@patch("requests.post")
@pytest.mark.parametrize("hook_type", BACKENDS)
def test_webhook_posts_expected_payload4(mock_post, mock_request, hook_type):
    """ProblemUpdated (severity unchanged) does not forward."""
    mock_request.return_value = MagicMock(ok=True, status_code=200)
    mock_post.return_value = Mock(status_code=BACKEND_SUCCESS_STATUS[hook_type], content=b"ok")
    yaml_str = _one_webhook_config(hook_type, filters_enabled=False)
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload_update_same, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    if hook_type == "github":
        assert mock_request.call_count == 0
    else:
        assert mock_post.call_count == 0


@patch("requests.request")
@patch("requests.post")
@pytest.mark.parametrize("hook_type", BACKENDS)
def test_webhook_posts_expected_payload_filtered(mock_post, mock_request, hook_type):
    """Payload matching label filter is forwarded to the configured backend."""
    # test_payload_for_filters is ProblemCleared; GitHub ignores it (no API calls)
    if hook_type == "github":
        mock_request.return_value = MagicMock(ok=True, status_code=200, json=lambda: [])
    else:
        mock_request.return_value = MagicMock(ok=True, status_code=200)
    mock_post.return_value = Mock(status_code=BACKEND_SUCCESS_STATUS[hook_type], content=b"ok")
    yaml_str = _one_webhook_config(
        hook_type,
        filters_enabled=True,
        filter_values=[
            {
                "field": "labels.k8s.cluster.name",
                "operator": "in",
                "value": ["my-important-services-cluster"],
            }
        ],
    )
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload_for_filters, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    if hook_type == "github":
        # GitHub returns 200 for ProblemCleared without calling create; no list issues either
        assert mock_request.call_count == 0
    else:
        assert mock_post.call_count == 1
        assert mock_post.call_args_list[0].args[0] == _expected_url(hook_type)


# Multi-webhook (Slack-only) scenario tests: filter matching with two webhooks
@patch("requests.post")
def test_webhook_multi_slack_matching(mock_post):
    """Two Slack webhooks with different filters; payload matches both (severity High + name Malfunction + impactsSLO)."""
    mock_post.return_value = Mock(status_code=202, content=b"ok")
    mock_post.side_effect = [Mock(status_code=202), Mock(status_code=202)]
    _setup_webhooks(yaml_text)
    payload_both = {**test_payload, "slos": [{}]}  # impactsSLO true so slack-malfunction-slo also matches
    client = app.test_client()
    resp = client.post(
        "/webhook", json=payload_both, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    assert mock_post.call_count == 2


@patch("requests.post")
def test_webhook_slack_label_filter(mock_post):
    """Single webhook with labels.k8s.cluster.name filter (slack-all-alerts)."""
    mock_post.return_value = Mock(status_code=202, content=b"ok")
    _setup_webhooks(config_test_yaml)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload_for_filters, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    assert mock_post.call_count == 1
    assert mock_post.call_args_list[0].args[0] == "http://test_slack"


def test_webhook_unauthorized_no_header():
    """POST without Authorization returns 401."""
    _setup_webhooks(_one_webhook_config("slack", filters_enabled=False))
    client = app.test_client()
    resp = client.post("/webhook", json=test_payload)
    assert resp.status_code == 401
    assert b"Unauthorized" in resp.data


def test_webhook_unauthorized_wrong_token():
    """POST with wrong Bearer token returns 401."""
    _setup_webhooks(_one_webhook_config("slack", filters_enabled=False))
    client = app.test_client()
    resp = client.post(
        "/webhook",
        json=test_payload,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


@patch("requests.post")
def test_webhook_no_matching_webhooks(mock_post):
    """When no webhooks match the payload, returns 200 and does not call any backend."""
    yaml_str = _one_webhook_config(
        "slack",
        filters_enabled=True,
        filter_values=[{"field": "severity", "operator": "in", "value": ["Critical"]}],
    )
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    assert b"No matching webhooks" in resp.data
    assert mock_post.call_count == 0


@patch("causely_notification.template.requests.request")
def test_webhook_template_renders_and_posts(mock_request):
    """Template webhook renders Jinja2 body and POSTs to URL."""
    mock_request.return_value = Mock(status_code=200, content=b"ok")
    yaml_str = textwrap.dedent("""
        webhooks:
          - name: "template-test"
            hook_type: "template"
            url: "https://example.com/template"
            filters:
              enabled: false
            template:
              content_type: "application/json"
              body: '{"title": "[[ name ]]", "priority": "[[ severity ]]"}'
        """)
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    assert mock_request.call_count == 1
    assert mock_request.call_args[0][0] == "POST"
    assert mock_request.call_args[0][1] == "http://test_template"
    body = mock_request.call_args[1]["data"]
    assert body == '{"title": "Malfunction", "priority": "High"}'
    assert mock_request.call_args[1]["headers"]["Content-Type"] == "application/json"


@patch("requests.post")
def test_webhook_all_forwards_fail_returns_500(mock_post):
    """When all forwards fail (e.g. 404), returns 500."""
    mock_post.return_value = Mock(status_code=404, content=b"Not Found")
    yaml_str = _one_webhook_config("slack", filters_enabled=False)
    _setup_webhooks(yaml_str)
    client = app.test_client()
    resp = client.post(
        "/webhook", json=test_payload, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 500
    assert b"Failed to forward" in resp.data
    assert mock_post.call_count == 1
