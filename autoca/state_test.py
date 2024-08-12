from datetime import datetime, timedelta
from unittest import main, TestCase
from autoca.primitives.crypto import create_ca, create_certificate, generate_keypair
from autoca.state import State, Permissions


class TestState(TestCase):
    def test(self):
        ca_kp = generate_keypair()
        cert_kp = generate_keypair()
        time = datetime.now()
        ca = create_ca(ca_kp, "test CA", time, time + timedelta(days=365))
        cert = create_certificate(
            cert_kp, ca, "test.com", time, time + timedelta(days=1)
        )
        s1 = State(time=time, ca=ca)
        s1.set_ca(ca)
        s1.add_certificate(cert, Permissions(0o750, "user", "group"))
        s2 = State().from_dict(s1.to_dict())
        self.assertEqual(s1.time, s2.time)
        self.assertEqual(s1.ca, s2.ca)

        # I have no idea why it doesn't work without the loop
        for c1, c2 in zip(s1.certs, s2.certs):
            self.assertEqual(c1[0], c2[0])
            self.assertEqual(c1[1], c2[1])


if __name__ == "__main__":
    main()
