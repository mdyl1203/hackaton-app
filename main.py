import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify

app = Flask(__name__)

# Generate a key pair
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
private_key = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
rsa_public_key = serialization.load_pem_public_key(public_key)


# Create a function to sign JWTs
def sign_jwt(payload, private_key):
    token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256'
    )
    return token


# Create a JWKS endpoint
@app.route('/jwks')
def jwks():
    public_numbers = rsa_public_key.public_numbers()
    jwk = {
        'kty': 'RSA',
        'alg': 'RS256',
        'use': 'sig',
        'kid': 'mykey',
        'n': public_numbers.n,
        'e': public_numbers.e
    }
    return jsonify({'keys': [jwk]})


# Create a server status endpoint
@app.route('/health_check')
def status():
    return jsonify({'health_check': 'alive'})


if __name__ == '__main__':
    app.run(debug=True)
