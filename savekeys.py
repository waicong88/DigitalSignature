from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_key = private_key.public_key()
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save private key
with open('private_key.pem', 'wb') as pem_out:
    pem_out.write(pem_private)

# Save public key
with open('public_key.pem', 'wb') as pem_out:
    pem_out.write(pem_public)

print("Keys generated and saved successfully.")
