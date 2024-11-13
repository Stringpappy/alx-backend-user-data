#!/usr/bin/env python3
""" Module of Index views
"""
from flask import jsonify, abort
from api.v1.views import app_views
from flask import Blueprint, abort


""" Create a Blueprint"""
index_bp = Blueprint('index', __name__)

""" Route that raises a 401 error"""
@index_bp.route('/api/v1/unauthorized', methods=['GET'])
def unauthorized():
    abort(401)

@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """ GET /api/v1/status
    Return:
      - the status of the API
    """
    return jsonify({"status": "OK"})


@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """ GET /api/v1/stats
    Return:
      - the number of each objects
    """
    from models.user import User
    stats = {}
    stats['users'] = User.count()
    return jsonify(stats)
