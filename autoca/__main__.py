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

root_path = Path(config.storage)
db_path = root_path.joinpath("db.toml")
try:
    state = State.from_file(db_path)
except FileNotFoundError:
    error("Database file not found: Path %s", db_path)
    state = State()
except:
    import traceback
    error("Could not parse database file: %r", traceback.format_exc())
    state = State()

if not state.initialized:
    time = datetime.now()
    kp = generate_keypair()
    ca = create_ca(kp, config.ca.cn, time, time + timedelta(days=config.ca.duration))
    state.set_ca(ca)
    # I have to force the sync to fs in order to set new CA
    state.update_fs(None, root_path)
    assert state.initialized

# Deep copy can't be done as RSAPrivateKey cannot be pickled
new_state = State().from_dict(state.to_dict())

# We should check if the CA in config is changed and then modify the state

now = datetime.now()
month = datetime(year=now.year, month=now.month, day=1)
# Add new domains
cert_domains = list(map(lambda c: c.domain, state.certs))
for domain in config.certificates.domains:
    if domain not in cert_domains:
        info("Adding cert for domain %s", domain)
        kp = generate_keypair()
        cert = create_certificate(kp, new_state.ca, domain, month, month + timedelta(days=config.certificates.duration))
        new_state.add_certificate(cert)

# Update expired certs
for c in state.certs():
    if c.end <= now:
        info("Updating certificate for %s", domain)
        kp = generate_keypair()
        cert = create_certificate(kp, new_state.ca, c.domain, month, month + timedelta(days=config.certificates.duration))
        new_state.delete_certificate(cert)
        new_state.add_certificate(cert)


new_state.update_fs(state, root_path)

info("Saving DB")
debug("db: %r", new_state.to_dict())

new_state.to_file(db_path)

info("Ended autoca")
