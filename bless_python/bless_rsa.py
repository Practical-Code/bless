from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization as crypto_serialization

def gen_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    return private_key


def load_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key

def save_privkey(private_key, filename, password):
   pem =  private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.BestAvailableEncryption(password)
   )
   with open(filename, 'wb') as pem_out:
       pem_out.write(pem)

def save_pubkey(private_key, filename):
    public_key = private_key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )
    with open(filename, 'wb') as pem_out:
       pem_out.write(public_key)


if __name__ == '__main__':
    pk = gen_key()
    save_privkey(pk, 'privkey.pem', b'abc123')
    save_pubkey(pk, 'pubkey.pem')
