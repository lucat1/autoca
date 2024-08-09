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
from grp import getgrnam

from autoca.primitives.crypto import generate_keypair, create_certificate
from autoca.state import State, Permissions
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
class Host:
    domain: str
    user: str

@dataclass
class CAConfig:
    cn: str
    duration: int = 365 * 60 # ~ 60ys

@dataclass
class CertificatesConfig:
    duration: int = 60 # ~ 2 starts
    domains: list[str] = field(default_factory=list)

@dataclass
class Config:
    storage: str
    ca: CAConfig
    certificates: CertificatesConfig
    hosts: list[Host]

def read_config(path: Path):
    config_file = open(path, mode="rb")
    return from_dict(data_class=Config, data=parse_toml(config_file))

config_path = Path(environ[CONFIG_PATH_ENV] if CONFIG_PATH_ENV in environ else "/etc/autoca/autoca.toml")
config = read_config(config_path)

# Checks for config
for h in config.hosts:
    try:
        getgrnam(h.user)
    except KeyError:
        error("Group '%s' not found, can't continue", h.user)
        exit(1)

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
duration = timedelta(days=config.certificates.duration)
duration_halfed = duration // 2
start = datetime.fromtimestamp((now.timestamp() // duration_halfed.total_seconds()) * duration_halfed.total_seconds())
info("start: " + str(start))
info("renew: " + str(start + duration_halfed))
info("expired: " + str(start + duration))

# Add new hosts
cert_domains = [c[0].domain for c in state.certs]
for host in config.hosts:
    if host.domain not in cert_domains:
        info("Adding cert for domain %s", host.domain)
        kp = generate_keypair()
        cert = create_certificate(kp, new_state.ca, host.domain, start, start + duration)
        new_state.add_certificate(cert, Permissions(permissions=0o640, user="root", group=host.user))

# Update expired certs
for c in state.certs:
    if now >= c[0].start + duration_halfed:
        info("Updating certificate for %s", c[0].domain)
        kp = generate_keypair()
        cert = create_certificate(kp, new_state.ca, c[0].domain, start, start + duration)
        new_state.delete_certificate(cert)
        new_state.add_certificate(cert, Permissions(permissions=0o640, user="root", group=host.user))


new_state.update_fs(state, root_path)

info("Saving DB")
debug("db: %r", new_state.to_dict())

new_state.to_file(db_path)

info("Ended autoca")
