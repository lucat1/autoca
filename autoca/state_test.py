from unittest import main, TestCase
from autoca.state import KeyPair
from autoca.crypto import generate_keypair

class TestKeyPair(TestCase):
    def test_from_dict(self):
        kp1 = generate_keypair()
        kp2 = KeyPair().from_dict(kp1.to_dict())
        self.assertEqual(kp1.key_bytes, kp2.key_bytes)
        self.assertEqual(kp1.public_key_bytes, kp2.public_key_bytes)

    def test_to_dict(self):
        kp = generate_keypair()
        self.assertEqual(kp.to_dict(), {"key": kp.key_bytes})

if __name__ == '__main__':
    main()
