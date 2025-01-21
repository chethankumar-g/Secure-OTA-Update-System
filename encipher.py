import base64
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def ascon_permutation(state):
    for _ in range(6):
        state = [((x >> 1) | (x << (64 - 1))) & ((1 << 64) - 1) for x in state]
        state[0] ^= state[1] ^ state[2]
    return state

def ascon_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    state = [int.from_bytes(key[:8], 'big'), int.from_bytes(key[8:], 'big'),
             int.from_bytes(nonce[:8], 'big'), int.from_bytes(nonce[8:], 'big'), 0]
    
    state = ascon_permutation(state)

    ciphertext = b''
    for i in range(0, len(plaintext), 8):
        block = int.from_bytes(plaintext[i:i + 8].ljust(8, b'\x00'), 'big')
        state[0] ^= block
        ciphertext += (state[0] & ((1 << 64) - 1)).to_bytes(8, 'big')
        state = ascon_permutation(state)
    return nonce + ciphertext

def ascon_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    state = [int.from_bytes(key[:8], 'big'), int.from_bytes(key[8:], 'big'),
             int.from_bytes(nonce[:8], 'big'), int.from_bytes(nonce[8:], 'big'), 0]

    state = ascon_permutation(state)

    plaintext = b''
    for i in range(16, len(ciphertext), 8):
        block = int.from_bytes(ciphertext[i:i + 8], 'big')
        plaintext_block = state[0] ^ block
        plaintext += plaintext_block.to_bytes(8, 'big').rstrip(b'\x00')
        state[0] = block
        state = ascon_permutation(state)

    return plaintext

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'OTA Update Key',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def encrypt_update(content: bytes, shared_key: bytes) -> str:
    nonce = os.urandom(16)  # 16-byte nonce for Ascon
    encrypted_content = ascon_encrypt(content, shared_key, nonce)
    return base64.b64encode(encrypted_content).decode()

def decrypt_update(encrypted_content: bytes, shared_key: bytes) -> str:
    encrypted_data = base64.b64decode(encrypted_content)
    nonce = encrypted_data[:16]  # Extract the 16-byte nonce
    ciphertext = encrypted_data[16:]
    decrypted_content = ascon_decrypt(ciphertext, shared_key, nonce)
    return decrypted_content.decode()