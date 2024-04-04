import os.path

from crypto_engines.crypto.SymmetricEncryption import SymmetricEncryption
from crypto_engines.crypto.KeyEncapsulation import KEM
from crypto_engines.crypto.DigitalSigning import DigitalSigning
from crypto_engines.tools.KeyPair import KeyPair
from crypto_engines.tools.secure_bytes import SecureBytes


def test_aes():
    key = SymmetricEncryption.generate_key()
    plaintext = SecureBytes(b"Hello, World!")
    ciphertext1 = SymmetricEncryption.encrypt(plaintext, key)
    ciphertext2 = SymmetricEncryption.encrypt(plaintext, key)
    print(ciphertext1.raw)
    print(ciphertext2.raw)

    decrypted_plaintext1 = SymmetricEncryption.decrypt(ciphertext1, key)
    decrypted_plaintext2 = SymmetricEncryption.decrypt(ciphertext2, key)
    print(decrypted_plaintext1.raw)
    print(decrypted_plaintext2.raw)


def test_kyber():
    # A and B have key pairs
    key_pair_a = KEM.generate_key_pair()
    key_pair_b = KEM.generate_key_pair()

    print(key_pair_a.public_key.length, key_pair_a.public_key)
    print(key_pair_a.secret_key.length, key_pair_a.secret_key)
    print(key_pair_b.public_key)
    print(key_pair_b.secret_key)
    print("-" * 100)

    # A creates the key and encapsulated key
    kem_key_pair_a = KEM.kem_wrap(key_pair_b.public_key)
    print(kem_key_pair_a.decapsulated_key)
    print(kem_key_pair_a.encapsulated_key)
    print("-" * 100)

    # B unwraps the key
    kem_key_pair_b = KEM.kem_unwrap(key_pair_b.secret_key, kem_key_pair_a.encapsulated_key)
    print(kem_key_pair_b.decapsulated_key)
    print(kem_key_pair_b.encapsulated_key)
    print("-" * 100)


def test_signature():
    key_pair = DigitalSigning.generate_key_pair()
    message = SecureBytes(b"Hello, World!")
    their_id = SecureBytes(b"Recipient")
    signed_message = DigitalSigning.sign(key_pair.secret_key, message, their_id)
    is_verified = DigitalSigning.verify(key_pair.public_key, signed_message, their_id)
    print(is_verified)


def test_key_export():
    path = os.path.abspath("./_keys/tmp")

    key_pair = DigitalSigning.generate_key_pair()
    key_pair.export(path, "test1")

    imported = KeyPair().import_(path, "test1")
    assert key_pair.secret_key == imported.secret_key
    assert key_pair.public_key == imported.public_key


if __name__ == "__main__":
    test_key_export()
