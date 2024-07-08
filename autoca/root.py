from os.path import join
from pathlib import Path
from ownca import CertificateAuthority

def root(storage: Path, path: str, name: str, exp: int = 65537, key_size = 4096):
    ca = CertificateAuthority(
        ca_storage=join(storage, path),
        common_name=name,
        public_exponent=exp,
        key_size=key_size,
    )
    print(ca, ca.status)
