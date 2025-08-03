from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields

app = Flask(__name__)
api = Api(app, title="Network Diagnostic API", version="1.0", description="A demo API for network diagnostics")

# Models for input/output validation
ping_model = api.model('Ping', {
    'target': fields.String(required=True, description="Target to ping", example="8.8.8.8")
})

dns_model = api.model('DNS', {
    'domain': fields.String(required=True, description="Domain to resolve", example="www.google.com")
})

@api.route('/api/ping')
class Ping(Resource):
    @api.expect(ping_model)
    def post(self):
        data = request.json
        target = data.get("target")
        return {"target": target, "result": "Ping successful"}

@api.route('/api/dns')
class DNS(Resource):
    @api.expect(dns_model)
    def post(self):
        data = request.json
        domain = data.get("domain")
        return {"domain": domain, "ip": "8.8.8.8"}

if __name__ == '__main__':
    app.run(debug=True)
