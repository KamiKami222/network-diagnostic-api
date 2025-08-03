import sqlite3
import secrets
import hashlib
import subprocess
import socket
from datetime import datetime
from flask import Flask, request, send_file
from flask_restx import Api, Resource, fields
import os
import whois


app = Flask(__name__)
api = Api(app, title="Network Diagnostic API", version="1.0", description="An API for network diagnostics.")

# Database connection helpers
def connect_logs_db():
    return sqlite3.connect("logs.db")

def connect_internal_db():
    return sqlite3.connect("internal.db")

# Hashing helper function
def hash_api_key(api_key):
    """Hash the API key using SHA-256."""
    return hashlib.sha256(api_key.encode()).hexdigest()

# Initialize databases
def initialize_databases():
    # Create visible database (logs.db)
    with connect_logs_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS api_key_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hashed TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        );
        """)

    # Create internal database (internal.db)
    with connect_internal_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS internal_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hashed TEXT NOT NULL UNIQUE
        );
        """)

# API models
auth_model = api.model('API Key Request', {})  # Empty request body for API key generation
ping_model = api.model('Ping Request', {
    'target': fields.String(required=True, description="Target to ping", example="8.8.8.8")
})
dns_model = api.model('DNS Request', {
    'domain': fields.String(required=True, description="Domain to resolve", example="www.google.com")
})
traceroute_model = api.model('Traceroute Request', {
    'target': fields.String(required=True, description="Target to traceroute", example="8.8.8.8")
})

# Namespace
diag_ns = api.namespace('api/diag', description="Network Diagnostic Tools")
api.add_namespace(diag_ns)  # Explicitly register namespace for debugging

# Swagger JSON Download
@app.route('/api/swagger-download', methods=['GET'])
def download_swagger():
    """Download the Swagger JSON file."""
    file_path = os.path.join(app.root_path, 'swagger.json')
    return send_file(file_path, as_attachment=True, download_name='swagger.json')

# Generate a new API key
@app.route('/api/key', methods=['POST'])
def generate_api_key():
    """Generate a new API key."""
    api_key = secrets.token_urlsafe(32)
    api_key_hashed = hash_api_key(api_key)
    created_at = datetime.now()

    # Deactivate all existing keys in logs.db
    with connect_logs_db() as conn:
        conn.execute("UPDATE api_key_logs SET status = 'inactive'")

    # Insert the new key as active in logs.db
    with connect_logs_db() as conn:
        conn.execute(
            "INSERT INTO api_key_logs (api_key_hashed, created_at, status) VALUES (?, ?, 'active')",
            (api_key_hashed, created_at)
        )

    # Replace the key in internal.db
    with connect_internal_db() as conn:
        conn.execute("DELETE FROM internal_keys")  # Clear the internal keys
        conn.execute(
            "INSERT INTO internal_keys (api_key_hashed) VALUES (?)",
            (api_key_hashed,)
        )

    return {"message": "New API key generated.", "api_key": api_key}

# Validate API key
def validate_api_key(provided_key):
    """Check if the provided API key is valid."""
    provided_key_hashed = hash_api_key(provided_key)

    with connect_internal_db() as conn:
        cursor = conn.execute(
            "SELECT 1 FROM internal_keys WHERE api_key_hashed = ?",
            (provided_key_hashed,)
        )
        return cursor.fetchone() is not None

# Ping Function
def ping(target):
    """Perform a ping using the Windows ping command."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)

@diag_ns.route('/ping')
class Ping(Resource):
    @api.expect(ping_model)
    def post(self):
        """Ping a target."""
        api_key = request.headers.get('x-api-key')
        if not api_key:
            api.abort(400, "API key is missing in headers.")

        if not validate_api_key(api_key):
            api.abort(401, "Unauthorized: Invalid API key.")

        data = request.get_json()
        if not data:
            api.abort(400, "Request body is missing.")

        target = data.get("target")
        if not target:
            api.abort(400, "Target is required.")

        result = ping(target)
        return {"target": target, "result": result}

# DNS Lookup Function
def dns_lookup(domain):
    """Perform DNS lookup for a given domain."""
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip}
    except socket.gaierror:
        return {"error": "Unable to resolve domain"}

@diag_ns.route('/dns')
class DNSLookup(Resource):
    @api.expect(dns_model)
    def post(self):
        """Perform DNS lookup."""
        api_key = request.headers.get('x-api-key')
        if not api_key:
            api.abort(400, "API key is missing in headers.")

        if not validate_api_key(api_key):
            api.abort(401, "Unauthorized: Invalid API key.")

        data = request.get_json()
        if not data:
            api.abort(400, "Request body is missing.")

        domain = data.get("domain")
        if not domain:
            api.abort(400, "Domain is required.")

        result = dns_lookup(domain)
        return result

# Traceroute Function
def traceroute(target):
    """Perform traceroute using the Windows tracert command."""
    try:
        result = subprocess.run(
            ["tracert", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)

@diag_ns.route('/traceroute')
class Traceroute(Resource):
    @api.expect(traceroute_model)
    def post(self):
        """Perform traceroute."""
        api_key = request.headers.get('x-api-key')
        if not api_key:
            api.abort(400, "API key is missing in headers.")

        if not validate_api_key(api_key):
            api.abort(401, "Unauthorized: Invalid API key.")

        data = request.get_json()
        if not data:
            api.abort(400, "Request body is missing.")

        target = data.get("target")
        if not target:
            api.abort(400, "Target is required.")

        result = traceroute(target)
        return {"target": target, "result": result}

# Logs Endpoint
@diag_ns.route('/logs')
class Logs(Resource):
    def get(self):
        """View logs of API keys."""
        api_key = request.headers.get('x-api-key')
        if not api_key:
            api.abort(400, "API key is missing in headers.")

        if not validate_api_key(api_key):
            api.abort(401, "Unauthorized: Invalid API key.")

        with connect_logs_db() as conn:
            cursor = conn.execute("SELECT * FROM api_key_logs")
            logs = [
                {"id": row[0], "api_key_hashed": row[1], "created_at": row[2], "status": row[3]}
                for row in cursor.fetchall()
            ]
        return logs

# Define a new namespace for SOC tools
soc_ns = api.namespace('api/soc', description="SOC Analyst Tools")

whois_model = api.model('WHOIS Request', {
    'domain': fields.String(required=True, description="Domain to lookup", example="example.com")
})

# WHOIS Lookup Function
def perform_whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status
        }
    except Exception as e:
        return {"error": str(e)}

@soc_ns.route('/whois')
class WhoisLookup(Resource):
    @api.expect(whois_model)
    def post(self):
        """Perform WHOIS lookup on a domain."""
        api_key = request.headers.get('x-api-key')
        if not validate_api_key(api_key):
            api.abort(401, "Unauthorized")

        data = request.get_json()
        domain = data.get("domain")
        if not domain:
            api.abort(400, "Domain is required.")

        result = perform_whois_lookup(domain)
        return result


# Initialize databases at app startup
initialize_databases()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
