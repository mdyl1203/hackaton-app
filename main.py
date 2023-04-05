from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import base64

app = Flask(__name__)

# Generate an RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Convert the public key to a JWK
jwk = {
    "kty": "RSA",
    "kid": "my-key-id",
    "use": "sig",
    "alg": "RS256",
    "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).decode().rstrip('='),
    "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, 'big')).decode().rstrip('=')
}


# Define a route for the JWKS endpoint
@app.route('/jwks.json')
def jwks():
    return jsonify({'keys': [jwk]})


# Define a route for the protected resource
@app.route('/protected')
def protected():
    token = request.headers.get('Authorization').split(' ')[1]
    decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
    return jsonify(decoded_token)


@app.route('/status')
def status():
    return jsonify({'status': 'alive'})

if __name__ == '__main__':
    app.run()
