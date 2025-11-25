import hashlib
from app.utils.db import connect_internal_db

def hash_api_key(api_key):
    return hashlib.sha256(api_key.encode()).hexdigest()

def validate_api_key(provided_key):
    hashed = hash_api_key(provided_key)
    with connect_internal_db() as conn:
        cursor = conn.execute("SELECT 1 FROM internal_keys WHERE api_key_hashed = ?", (hashed,))
        return cursor.fetchone() is not None
