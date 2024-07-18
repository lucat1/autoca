from datetime import datetime, timedelta
from unittest import main, TestCase
from autoca.state import KeyPair, CA, Certificate
from autoca.crypto import generate_keypair, create_ca, create_certificate

class TestKeyPair(TestCase):
    def test(self):
        kp1 = generate_keypair()
        kp2 = KeyPair().from_dict(kp1.to_dict())
        self.assertEqual(kp1.key_bytes, kp2.key_bytes)
        self.assertEqual(kp1.public_key_bytes, kp2.public_key_bytes)

class TestCA(TestCase):
    def test(self):
        kp = generate_keypair()
        time = datetime.now()
        ca1 = create_ca(kp, "test CA", time, time + timedelta(days=365))
        ca2 = CA().from_dict(ca1.to_dict())
        self.assertEqual(ca1.key_bytes, ca2.key_bytes)
        self.assertEqual(ca1.public_key_bytes, ca2.public_key_bytes)
        self.assertEqual(ca1.sn, ca2.sn)
        self.assertEqual(ca1.start, ca2.start)
        self.assertEqual(ca1.end, ca2.end)
        self.assertEqual(ca1.certificate_bytes, ca2.certificate_bytes)

class TestCertificate(TestCase):
    def test(self):
        kp = generate_keypair()
        time = datetime.now()
        ca = create_ca(kp, "test CA", time, time + timedelta(days=365))
        cert1 = create_certificate(kp, ca, "test.com", time, time + timedelta(days=1))
        cert2 = Certificate().from_dict(cert1.to_dict())
        self.assertEqual(cert1.key_bytes, cert2.key_bytes)
        self.assertEqual(cert1.public_key_bytes, cert2.public_key_bytes)
        self.assertEqual(cert1.domain, cert2.domain)
        self.assertEqual(cert1.start, cert2.start)
        self.assertEqual(cert1.end, cert2.end)
        self.assertEqual(cert1.certificate_bytes, cert2.certificate_bytes)

if __name__ == '__main__':
    main()
