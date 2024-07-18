from datetime import datetime, timedelta
from dataclasses import dataclass
from dacite import from_dict
from tomllib import load as parse_toml
from typing import TypedDict, cast
from pathlib import Path
from logging import basicConfig as logger_config, debug, info, error
from logging import CRITICAL, FATAL, ERROR, WARNING, WARN, INFO, DEBUG
from os import environ

from autoca.primitives.crypto import generate_keypair
from autoca.state import State
from autoca.primitives import create_ca

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

info("Started autoca")

@dataclass
class CAConfig:
    cn: str
    duration: int = 365 * 60 # ~ 60ys

@dataclass
class CertificatesConfig:
    duration: int = 60 # ~ 2 months

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
    assert state.initialized

info("Saving DB")
debug("db: %r", state.to_dict())

state.to_file(db_path)

info("Ended autoca")
