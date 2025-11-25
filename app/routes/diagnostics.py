import secrets
import subprocess
import socket
from datetime import datetime
from flask import request, send_file, current_app
from flask_restx import Namespace, Resource, fields
import os
import logging


from app.utils.db import connect_logs_db, connect_internal_db
from app.utils.security import hash_api_key, validate_api_key

logging.getLogger('werkzeug').disabled = True
diag_ns = Namespace('diagnostics', description="Network Diagnostic Tools")

# Models
auth_model = diag_ns.model('API Key Request', {})
ping_model = diag_ns.model('Ping Request', {
    'target': fields.String(required=True, description="Target to ping", example="8.8.8.8")
})
dns_model = diag_ns.model('DNS Request', {
    'domain': fields.String(required=True, description="Domain to resolve", example="www.google.com")
})
traceroute_model = diag_ns.model('Traceroute Request', {
    'target': fields.String(required=True, description="Target to traceroute", example="8.8.8.8")
})

# Generate API Key
@diag_ns.route('/key')
class GenerateAPIKey(Resource):
    @diag_ns.expect(auth_model)
    def post(self):
        api_key = secrets.token_urlsafe(32)
        api_key_hashed = hash_api_key(api_key)
        created_at = datetime.now()
        client_ip = request.remote_addr or "unknown"

        # LOGS DB
        with connect_logs_db() as conn:
            # deactivate older keys from this IP only
            conn.execute(
                "UPDATE api_key_logs SET status = 'inactive' WHERE ip_address = ?",
                (client_ip,)
            )
            conn.execute(
                "INSERT INTO api_key_logs (api_key_hashed, ip_address, created_at, status) "
                "VALUES (?, ?, ?, 'active')",
                (api_key_hashed, client_ip, created_at)
            )

        # INTERNAL DB
        with connect_internal_db() as conn:
            conn.execute(
                "DELETE FROM internal_keys WHERE ip_address = ?",
                (client_ip,)
            )
            conn.execute(
                "INSERT INTO internal_keys (api_key_hashed, ip_address, created_at) "
                "VALUES (?, ?, ?)",
                (api_key_hashed, client_ip, created_at)
            )

        # 👉 Our own console line with the key, mimicking Werkzeug style
        log_line = (
            f'{client_ip} - "{api_key}" - '
            f'[{datetime.now().strftime("%d/%b/%Y %H:%M:%S")}] '
            f'"{request.method} {request.path} {request.environ.get("SERVER_PROTOCOL", "HTTP/1.1")}" 200'
        )
        print(log_line)  # <-- this will always show in the terminal

        # Response to client (no bound_ip)
        return {
            "message": "New API key generated.",
            "api_key": api_key
        }

# Ping
def ping(target):
    try:
        result = subprocess.run(["ping", "-n", "1", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

@diag_ns.route('/ping')
class Ping(Resource):
    @diag_ns.expect(ping_model)
    def post(self):
        api_key = request.headers.get('x-api-key')
        if not validate_api_key(api_key):
            diag_ns.abort(401, "Unauthorized")
        target = request.get_json().get("target")
        if not target:
            diag_ns.abort(400, "Target is required.")
        return {"target": target, "result": ping(target)}

# DNS
def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip}
    except socket.gaierror:
        return {"error": "Unable to resolve domain"}

@diag_ns.route('/dns')
class DNSLookup(Resource):
    @diag_ns.expect(dns_model)
    def post(self):
        api_key = request.headers.get('x-api-key')
        if not validate_api_key(api_key):
            diag_ns.abort(401, "Unauthorized")
        domain = request.get_json().get("domain")
        if not domain:
            diag_ns.abort(400, "Domain is required.")
        return dns_lookup(domain)

# Traceroute
def traceroute(target):
    try:
        result = subprocess.run(["tracert", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

@diag_ns.route('/traceroute')
class Traceroute(Resource):
    @diag_ns.expect(traceroute_model)
    def post(self):
        api_key = request.headers.get('x-api-key')
        if not validate_api_key(api_key):
            diag_ns.abort(401, "Unauthorized")
        target = request.get_json().get("target")
        if not target:
            diag_ns.abort(400, "Target is required.")
        return {"target": target, "result": traceroute(target)}

# Logs
@diag_ns.route('/logs')
class Logs(Resource):
    def get(self):
        with connect_logs_db() as conn:
            cursor = conn.execute("SELECT * FROM api_key_logs")
            logs = [{"id": row[0], "api_key_hashed": row[1], "created_at": row[2], "status": row[3]} for row in cursor.fetchall()]
        return logs

# Swagger Download
@diag_ns.route('/swagger-download')
class SwaggerDownload(Resource):
    def get(self):
        file_path = os.path.join(os.getcwd(), 'static', 'swagger.json')
        return send_file(file_path, as_attachment=True, download_name='swagger.json')
