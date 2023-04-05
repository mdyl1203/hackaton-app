from flask import Flask, jsonify
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Convert keys to JWK format
private_jwk = {
    'kty': 'RSA',
    'kid': 'my-key-id',
    'use': 'sig',
    'alg': 'RS256',
    'n': public_key.public_numbers().n,
    'e': public_key.public_numbers().e,
    'd': private_key.private_numbers().d,
    'p': private_key.private_numbers().p,
    'q': private_key.private_numbers().q,
    'dp': private_key.private_numbers().dmp1,
    'dq': private_key.private_numbers().dmq1,
    'qi': private_key.private_numbers().iqmp
}
public_jwk = {
    'kty': 'RSA',
    'kid': 'my-key-id',
    'use': 'sig',
    'alg': 'RS256',
    'n': public_key.public_numbers().n,
    'e': public_key.public_numbers().e
}


# Endpoint to get JWKs
@app.route('/jwks.json')
def jwks():
    return jsonify({
        'keys': [public_jwk]
    })


# Endpoint to generate and sign JWT
@app.route('/jwt')
def jwt_endpoint():
    payload = {'sub': '1234567890', 'name': 'John Doe'}
    encoded_jwt = jwt.encode(payload, private_key, algorithm='RS256')
    return encoded_jwt


# Create a server status endpoint
@app.route('/status')
def status():
    return jsonify({'status': 'alive'})


if __name__ == '__main__':
    app.run(debug=True)