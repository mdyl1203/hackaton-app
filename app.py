from flask import Flask, jsonify
from jwcrypto import jwk


app = Flask(__name__)


@app.route('/.well-known/jwks.json')
def jwks():
    with open('public_key.pem', 'rb') as f:
        public_key_pem = f.read()

    # Convert PEM keys to JWK format
    public_key_jwk = jwk.JWK.from_pem(public_key_pem)

    # Create JWKS dictionary
    jwks = {
        "keys": [
            public_key_jwk.export(as_dict=True)
        ]
    }

    return jsonify(jwks)


if __name__ == '__main__':
    app.run(debug=True)
