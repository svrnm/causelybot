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

from __future__ import annotations

import json
import os
import sys

import yaml
from flask import Flask
from flask import jsonify
from flask import request

from typing import Dict, Any

from causely_notification.filter import WebhookFilterStore
from causely_notification.github import forward_to_github
from causely_notification.jira import forward_to_jira
from causely_notification.opsgenie import forward_to_opsgenie
from causely_notification.slack import forward_to_slack
from causely_notification.teams import forward_to_teams
from causely_notification.opsgenie import forward_to_opsgenie
from causely_notification.debug import forward_to_debug
from causely_notification.template import forward_to_template

app = Flask(__name__)

def load_config():
    with open("/etc/causelybot/config.yaml", 'r') as stream:
        return yaml.safe_load(stream)


def get_config():
    return load_config()


EXPECTED_TOKEN = os.getenv("AUTH_TOKEN")

@app.route('/webhook', methods=['POST'])
def webhook_routing():
    # Check for Bearer token in Authorization header
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.split(" ")[1] == EXPECTED_TOKEN:
        payload = request.json
        
        # Log the received payload for debugging
        print("RECEIVED PAYLOAD:", json.dumps(payload), file=sys.stderr)
        
        # Check if the payload passes the filter
        matching_webhooks = filter_store.filter_payload(payload)

        notifType = payload.get("type", "ProblemDetected")
        # Specialized handling for problem updated, only send the notification
        # when it wasn't sent before, or it was sent before but the severity reduced
        if notifType == "ProblemUpdated":
            # put the payload old severity into the payload and check which webhooks
            # would have previously matched
            tempPayload = request.json
            oldSeverity = tempPayload.get("old_severity", "")
            if oldSeverity != "":
                tempPayload["severity"] = oldSeverity
                old_matches = filter_store.filter_payload(tempPayload)
                # Check if it matched before but didn't know - send an update
                # Check if it didn't match before but does not - send an update
                # Otherwise, no need to send an update - so get the webhooks that aren't in both sets
                new_matches = list(set(old_matches) ^ set(matching_webhooks))
                matching_webhooks = new_matches
        # If there are no matching webhooks, return 200 OK
        if not matching_webhooks:
            return jsonify({"message": "No matching webhooks found"}), 200
        # Forward the payload to all matching webhooks
        # Track successful and failed forwards
        successful_forwards = []
        failed_forwards = []

        for name in matching_webhooks:
            hook_url = webhook_lookup_map[name]['url']
            hook_type = webhook_lookup_map[name]['hook_type']
            hook_token = webhook_lookup_map[name]['token']
            hook_assignee = webhook_lookup_map[name].get('assignee')
            match hook_type.lower():  # case-insensitive
                case "teams":
                    response = forward_to_teams(payload, hook_url)
                case "slack":
                    response = forward_to_slack(payload, hook_url, hook_token)
                case "opsgenie":
                    response = forward_to_opsgenie(payload, hook_url, hook_token)
                case "jira":
                    response = forward_to_jira(payload, hook_url, hook_token)
                case "github":
                    response = forward_to_github(payload, hook_url, hook_token, assignee=hook_assignee)
                case "debug":
                    response = forward_to_debug(payload, hook_url, hook_token)
                case "template":
                    template_config = webhook_lookup_map[name].get("template") or {}
                    response = forward_to_template(
                        payload, hook_url, hook_token, template_config
                    )
                case _:
                    failed_forwards.append(f"Unknown hook type: {hook_type}")
                    continue

            if response.status_code in [200, 201, 202]:
                successful_forwards.append(name)
            else:
                print(f"Failed to forward to {name}: {response.content}", file=sys.stderr)
                failed_forwards.append(name)

        # Return appropriate response based on results
        # If all forwards are successful, return 200 (all successful)
        # If some forwards are successful and some are not, return 207 (partial success)
        # If all forwards fail, return 500 (all failed)
        if successful_forwards and not failed_forwards:
            print(f"Payload forwarded to: {', '.join(successful_forwards)}", file=sys.stderr)
            return jsonify({"message": f"Payload forwarded to: {', '.join(successful_forwards)}"}), 200
        elif successful_forwards and failed_forwards:
            print(
                f"Partially successful. Succeeded: {', '.join(successful_forwards)}, Failed: {', '.join(failed_forwards)}",
                file=sys.stderr)
            return jsonify({
                               "message": f"Partially successful. Succeeded: {', '.join(successful_forwards)}, Failed: {', '.join(failed_forwards)}"}), 207
        else:
            print(f"Failed to forward to any webhooks: {', '.join(failed_forwards)}", file=sys.stderr)
            return jsonify({"message": f"Failed to forward to any webhooks: {', '.join(failed_forwards)}"}), 500
    else:
        return jsonify({"message": "Unauthorized"}), 401

def populate_webhooks(webhooks):

    # Step 2: Initialize the webhook filter store
    filter_store = WebhookFilterStore()

    # Step 3: Map of webhook names to their (url, token) from environment variables
    webhook_lookup_map = {}

    for webhook in webhooks:
        # Extract the webhook name, type, url, and token
        webhook_name = webhook.get("name")  # REQUIRED
        if not webhook_name:
            raise ValueError("Webhook name is required in the configuration.")
        # Normalize the webhook name for environment variable lookup (uppercase and spaces to underscores)
        normalized_name = webhook_name.upper().replace(" ", "_")
        webhook_type = webhook.get("hook_type")  # REQUIRED
        if not webhook_type:
            raise ValueError("Webhook type is required in the configuration.")

        # Get the url and token and env vars.  In kubernetes this should be a
        # secret.  In docker, create env vars
        url_env_var = f"URL_{normalized_name}"
        token_env_var = f"TOKEN_{normalized_name}"
        url = os.getenv(url_env_var)
        token = os.getenv(token_env_var)

        if not url:
            raise ValueError(f"Missing environment variable '{
            url_env_var
            }' for webhook '{webhook_name}'")

        # Optional assignee (used by GitHub)
        assignee_env_var = f"ASSIGNEE_{normalized_name}"
        assignee = os.getenv(assignee_env_var)

        # Store the webhook URL, token, hook type, optional assignee, and template config in the lookup map
        entry = {
            'url': url,
            'token': token,
            'hook_type': webhook_type,
            'assignee': assignee,
        }
        if webhook_type.lower() == 'template':
            entry['template'] = webhook.get('template') or {}
        webhook_lookup_map[webhook_name] = entry

        # Extract and add filters for the webhook (if enabled)
        filters = webhook.get("filters", {})
        enabled = filters.get("enabled", False)
        filter_values = filters.get("values", [])

        # Add the webhook filters to the filter store
        filter_store.add_webhook_filters(webhook_name, filter_values, enabled)
    return filter_store, webhook_lookup_map

if __name__ == '__main__':
    # Step 1: Read the configuration file
    config = get_config()
    webhooks = config.get("webhooks", [])
    if not webhooks:
        raise ValueError("No webhooks found in the config.")
    filter_store, webhook_lookup_map = populate_webhooks(webhooks)
    # Start the application
    app.run(host='0.0.0.0', port=5000)