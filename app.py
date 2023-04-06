import base64
from flask import Flask, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


app = Flask(__name__)


@app.route('/.well-known/jwks.json')
def jwks():
    with open('public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        n_bytes = public_key.public_numbers().n.to_bytes((public_key.key_size + 7) // 8, byteorder='big')
        jwk = {
            'kty': 'RSA',
            'kid': 'qBaNXKwJvjxnGAuCv53Rtg',
            'use': 'sig',
            'n': base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('='),
            'e': "AQAB"
        }
        jwks = {
            'keys': [jwk]
        }
        return jsonify(jwks)


if __name__ == '__main__':
    app.run()
