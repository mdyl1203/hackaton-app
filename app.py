from flask import Flask
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import base64


app = Flask(__name__)


@app.route('/.well-known/jwks.json')
def jwk():
    # read private key from file
    with open('private_key.pem', 'rb') as f:
        private_key_pem = f.read()

    # read public key from file
    with open('public_key.pem', 'rb') as f:
        public_key_pem = f.read()

    # parse the keys from the PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    public_key = serialization.load_pem_public_key(
        public_key_pem
    )

    # extract the algorithm and key type from the keys
    if isinstance(private_key, rsa.RSAPrivateKey):
        key_type = "RSA"
        alg = "RS256"
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        key_type = "EC"
        alg = "ES256"
    else:
        raise ValueError("Unsupported key type")

    # extract the public key components
    if isinstance(public_key, rsa.RSAPublicKey):
        n = public_key.public_numbers().n
        e = public_key.public_numbers().e
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        x = public_key.public_numbers().x
        y = public_key.public_numbers().y
    else:
        raise ValueError("Unsupported key type")

    # construct the JWK
    jwk = {
        "kty": key_type,
        "alg": alg,
        "use": "sig",
    }

    if key_type == "RSA":
        jwk.update({
            "n": base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode(),
            "e": base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, 'big')).decode(),
            "d": base64.urlsafe_b64encode(
                private_key.private_numbers().d.to_bytes((private_key.private_numbers().d.bit_length() + 7) // 8,
                                                         'big')).decode(),
            "p": base64.urlsafe_b64encode(
                private_key.private_numbers().p.to_bytes((private_key.private_numbers().p.bit_length() + 7) // 8,
                                                         'big')).decode(),
            "q": base64.urlsafe_b64encode(
                private_key.private_numbers().q.to_bytes((private_key.private_numbers().q.bit_length() + 7) // 8,
                                                         'big')).decode(),
            "dp": base64.urlsafe_b64encode(private_key.private_numbers().dmp1.to_bytes(
                (private_key.private_numbers().dmp1.bit_length() + 7) // 8, 'big')).decode(),
            "dq": base64.urlsafe_b64encode(private_key.private_numbers().dmq1.to_bytes(
                (private_key.private_numbers().dmq1.bit_length() + 7) // 8, 'big')).decode(),
            "qi": base64.urlsafe_b64encode(private_key.private_numbers().iqmp.to_bytes(
                (private_key.private_numbers().iqmp.bit_length() + 7) // 8, 'big')).decode()
        })
    elif key_type == "EC":
        jwk.update({
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(x.to_bytes((x.bit_length() + 7) // 8, 'big')).decode(),
            "y": base64.urlsafe_b64encode(y.to_bytes((y.bit_length() + 7) // 8, 'big')).decode(),
            "d": base64.urlsafe_b64encode(private_key.private_numbers().private_value.to_bytes(
                (private_key.private_numbers().private_value.bit_length() + 7) // 8, 'big')).decode()
        })
    else:
        raise ValueError("Unsupported key type")

    return {"keys": [jwk]}