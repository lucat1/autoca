from datetime import datetime, timedelta
from dataclasses import dataclass, field
from dacite import from_dict
from tomllib import load as parse_toml
from typing import TypedDict, cast
from pathlib import Path
from logging import basicConfig as logger_config, getLogger, StreamHandler, debug, info, error
from logging import CRITICAL, FATAL, ERROR, WARNING, WARN, INFO, DEBUG
from os import environ
from sys import stdout

from autoca.primitives.crypto import generate_keypair, create_certificate
from autoca.state import State
from autoca.primitives import create_ca
from autoca.primitives.utils import create_symlink_if_not_present

CONFIG_PATH_ENV = "AUTOCA_CONFIG"
LOG_PATH_ENV = "AUTOCA_LOG"
LOGLEVEL_ENV = "AUTOCA_LOGLEVEL"

log_levels = {
    "CRITICAL" : CRITICAL,
    "FATAL" : FATAL,
    "ERROR" : ERROR,
    "WARNING" : WARNING,
    "WARN" : WARN,
    "INFO" : INFO,
    "DEBUG" : DEBUG
}

log_path = Path(environ[LOG_PATH_ENV] if LOG_PATH_ENV in environ else "/etc/autoca/latest.log")
loglevel = environ[LOGLEVEL_ENV] if LOGLEVEL_ENV in environ else "INFO"
logger_config(filename=log_path, level=log_levels[loglevel], filemode='a', format="%(asctime)s - %(message)s")
getLogger().addHandler(StreamHandler(stdout))

info("Started autoca")

@dataclass
class CAConfig:
    cn: str
    duration: int = 365 * 60 # ~ 60ys

@dataclass
class CertificatesConfig:
    duration: int = 60 # ~ 2 months
    domains: list[str] = field(default_factory=list)

@dataclass
class Config:
    storage: str
    ca: CAConfig
    certificates: CertificatesConfig

def read_config(path: Path):
    config_file = open(path, mode="rb")
    return from_dict(data_class=Config, data=parse_toml(config_file))

config_path = Path(environ[CONFIG_PATH_ENV] if CONFIG_PATH_ENV in environ else "/etc/autoca/autoca.toml")
config = read_config(config_path)

db_path = Path(config.storage).joinpath("db.toml")
try:
    state = State.from_file(db_path)
except:
    import traceback
    error("Could not parse database file: %r", traceback.format_exc())
    state = State()

if not state.initialized:
    time = datetime.now()
    kp = generate_keypair()
    ca = create_ca(kp, config.ca.cn, time, time + timedelta(days=config.ca.duration))
    state.set_ca(ca)

    month = datetime(year=time.year, month=time.month, day=1)
    for domain in config.certificates.domains:
        kp = generate_keypair()
        cert = create_certificate(kp, state.ca, domain, month, month + timedelta(days=config.certificates.duration))
        state.add_certificate(cert)
        
    assert state.initialized

now = datetime.now()
month = datetime(year=now.year, month=now.month, day=1)
for cert in state.certs:
    if cert.domain not in config.certificates.domains:
        info("Deleting cert for domain %s as not present in config", cert.domain)
        state.delete_certificate(cert)
        continue

# Deep copy can't be done as RSAPrivateKey cannot be pickled
new_state = State().from_dict(state.to_dict())

# Add new domains
for domain in config.certificates.domains:
    cert_domains = map(lambda c: c.domain, new_state.certs)
    if domain not in cert_domains:
        info("Adding cert for domain %s", new_cert.domain)
        kp = generate_keypair()
        cert = create_certificate(kp, new_state.ca, domain, month, month + timedelta(days=config.certificates.duration))
        new_state.add_certificate(cert)


info("Saving DB")
debug("db: %r", new_state.to_dict())

new_state.to_file(db_path)

info("Writing files")
new_state.certs_to_files(Path(config.storage))

info("Ended autoca")
