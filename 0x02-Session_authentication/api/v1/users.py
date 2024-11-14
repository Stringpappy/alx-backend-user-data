from flask import Flask, request, jsonify
from functools import wraps
import base64

app = Flask(__name__)

# Sample users for demonstration
USERS = {
    "admin": "password123",  # username:password
}

def check_auth(username, password):
    """Verify if the username and password are correct."""
    return USERS.get(username) == password

def authenticate():
    """Send a 401 response requesting user credentials."""
    return jsonify({"message": "Unauthorized"}), 401

def requires_auth(f):
    """Decorator to require basic authentication for API endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth:
            return authenticate()
        auth_type, auth_string = auth.split(' ', 1)
        if auth_type.lower() != 'basic':
            return authenticate()

        try:
            # Decode the base64 encoded 'username:password' string
            decoded_auth = base64.b64decode(auth_string).decode('utf-8')
            username, password = decoded_auth.split(':', 1)
        except (TypeError, ValueError):
            return authenticate()

        if not check_auth(username, password):
            return authenticate()

        return f(*args, **kwargs)

    return decorated_function

@app.route('/api/v1/users', methods=['GET'])
@requires_auth
def get_users():
    """Retrieve a list of all users."""
    return jsonify(USERS)

@app.route('/api/v1/users', methods=['POST'])
@requires_auth
def create_user():
    """Create a new user."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if username and password:
        USERS[username] = password
        return jsonify({"message": "User created successfully"}), 201
    return jsonify({"message": "Invalid data"}), 400

@app.route('/api/v1/users/<user_id>', methods=['GET'])
@requires_auth
def get_user(user_id):
    """Retrieve a specific user by ID."""
    user = USERS.get(user_id)
    if user:
        return jsonify({user_id: user})
    return jsonify({"message": "User not found"}), 404

@app.route('/api/v1/users/<user_id>', methods=['PUT'])
@requires_auth
def update_user(user_id):
    """Update a specific user by ID."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()
    password = data.get("password")
    if password:
        USERS[user_id] = password
        return jsonify({"message": f"User {user_id} updated successfully"}), 200
    return jsonify({"message": "Invalid data"}), 400

@app.route('/api/v1/users/<user_id>', methods=['DELETE'])
@requires_auth
def delete_user(user_id):
    """Delete a specific user by ID."""
    user = USERS.pop(user_id, None)
    if user:
        return jsonify({"message": f"User {user_id} deleted successfully"}), 200
    return jsonify({"message": "User not found"}), 404

if __name__ == '__main__':
    """Run the Flask application."""
    app.run(debug=True)
