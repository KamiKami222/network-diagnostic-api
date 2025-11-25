from flask import Flask
from flask_restx import Api
from app.routes.diagnostics import diag_ns
from app.utils.db import initialize_databases

def create_app():
    app = Flask(__name__)
    api = Api(app, title="Network Diagnostic API", version="1.0", description="An API for network diagnostics.")

    api.add_namespace(diag_ns)
    initialize_databases()

    return app
