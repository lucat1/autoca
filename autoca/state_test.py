from unittest import main, TestCase
from autoca.state import KeyPair, CA
from autoca.crypto import generate_keypair, create_ca

class TestKeyPair(TestCase):
    def test(self):
        kp1 = generate_keypair()
        kp2 = KeyPair().from_dict(kp1.to_dict())
        self.assertEqual(kp1.key_bytes, kp2.key_bytes)
        self.assertEqual(kp1.public_key_bytes, kp2.public_key_bytes)

class TestCA(TestCase):
    def test(self):
        kp = generate_keypair()
        ca1 = create_ca(kp, "test CA", 0, 1024)
        ca2 = CA().from_dict(ca1.to_dict())
        self.assertEqual(ca1.key_bytes, ca2.key_bytes)
        self.assertEqual(ca1.public_key_bytes, ca2.public_key_bytes)
        self.assertEqual(ca1.sn, ca2.sn)
        self.assertEqual(ca1.start, ca2.start)
        self.assertEqual(ca1.end, ca2.end)
        self.assertEqual(ca1.certificate, ca2.certificate)

if __name__ == '__main__':
    main()
