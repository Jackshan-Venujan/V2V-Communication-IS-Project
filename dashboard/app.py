"""Flask dashboard for real-time V2V security monitoring."""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import Flask, jsonify, render_template, request


def create_app(node) -> Flask:
    """Create the Flask application bound to a VehicleNode instance.

    Routes:
        GET  /              — Render the dashboard HTML page.
        GET  /api/state     — Return full node state as JSON (polled every 3s).
        GET  /api/alerts    — Return security alerts as JSON.
        POST /api/clear-alerts — Clear all alerts.
    """
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))

    @app.after_request
    def _cors(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/state")
    def api_state():
        return jsonify(node.get_state())

    @app.route("/api/alerts")
    def api_alerts():
        return jsonify({"alerts": node.logger.get_alerts()})

    @app.route("/api/clear-alerts", methods=["POST"])
    def api_clear_alerts():
        node.logger.clear_alerts()
        return jsonify({"status": "cleared"})

    return app
