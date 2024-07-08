from tomllib import load as parse_toml
from typing import TypedDict, cast
from pathlib import Path
from logging import basicConfig as logger_config, fatal, info
from logging import CRITICAL, FATAL, ERROR, WARNING, WARN, INFO, DEBUG
from ownca import CertificateAuthority
from os import environ
from os.path import join

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

Root = TypedDict("Root", { "path": str, "name": str, "exp": int, "key_size": int, "years": int })
Config = TypedDict("Config", { "storage": str, "root": Root })

config_path = Path(environ[CONFIG_PATH_ENV] if CONFIG_PATH_ENV in environ else "/etc/autoca/autoca.toml")
config_file = open(config_path, mode="rb")
config: Config = cast(Config, parse_toml(config_file))

assert("storage" in config and config["storage"] is not None)

storage = Path(config["storage"])
root = CertificateAuthority(
    ca_storage=join(storage, config["root"]["path"]),
    maximum_days=7200, # 365 * config["root"]["years"],
    **config["root"],
)
info("Root CA OK")
print(root.status)

info("Ended autoca")
