from datetime import datetime, timedelta
from unittest import main, TestCase
from autoca.primitives.crypto import create_ca, create_certificate, generate_keypair
from autoca.state import State


class TestState(TestCase):
    def test(self):
        ca_kp = generate_keypair()
        cert_kp = generate_keypair()
        time = datetime.now()
        ca = create_ca(ca_kp, "test CA", time, time + timedelta(days=365))
        cert = create_certificate(
            cert_kp, ca, "test.com", time, time + timedelta(days=1), "user"
        )
        s1 = State(time=time, ca=ca)
        s1.set_ca(ca)
        s1.add_certificate(cert)
        s2 = State().from_dict(s1.to_dict())
        self.assertEqual(s1.time, s2.time)
        self.assertEqual(s1.ca, s2.ca)
        self.assertEqual(s1.certs, s2.certs)
        self.assertEqual(s1.links, s2.links)


if __name__ == "__main__":
    main()
