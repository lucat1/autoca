from datetime import datetime, timedelta
from dataclasses import dataclass, field
from dacite import from_dict
from tomllib import load as parse_toml
from pathlib import Path
from logging import (
    basicConfig as logger_config,
    getLogger,
    StreamHandler,
    debug,
    info,
    error,
)
from logging import CRITICAL, FATAL, ERROR, WARNING, WARN, INFO, DEBUG
from os import environ, getuid
from sys import stdout
from grp import getgrnam

from autoca.primitives.crypto import generate_keypair, create_certificate
from autoca.state import State
from autoca.primitives import create_ca
from autoca.writer import SUPER_UID, ChangeKind, Writer

CONFIG_PATH_ENV = "AUTOCA_CONFIG"
LOG_PATH_ENV = "AUTOCA_LOG"
LOGLEVEL_ENV = "AUTOCA_LOGLEVEL"

log_levels = {
    "CRITICAL": CRITICAL,
    "FATAL": FATAL,
    "ERROR": ERROR,
    "WARNING": WARNING,
    "WARN": WARN,
    "INFO": INFO,
    "DEBUG": DEBUG,
}

@dataclass
class Host:
    domain: str
    user: str


@dataclass
class CAConfig:
    cn: str
    duration: int = 365 * 60  # ~ 60ys


@dataclass
class CertificatesConfig:
    duration: int = 60  # ~ 2 starts
    domains: list[str] = field(default_factory=list)


@dataclass
class Config:
    storage: str
    shared_group: str

    ca: CAConfig
    certificates: CertificatesConfig
    hosts: list[Host]

def main() -> None:
    log_path = Path(
        environ[LOG_PATH_ENV] if LOG_PATH_ENV in environ else "/etc/autoca/latest.log"
    )
    loglevel = environ[LOGLEVEL_ENV] if LOGLEVEL_ENV in environ else "INFO"
    logger_config(
        filename=log_path,
        level=log_levels[loglevel],
        filemode="a",
        format="%(asctime)s - %(message)s",
    )
    getLogger().addHandler(StreamHandler(stdout))

    if getuid() != SUPER_UID:
        print("autoca must be run as root!")
        exit(1)

    info("Started autoca")

    config_path = Path(
        environ[CONFIG_PATH_ENV]
        if CONFIG_PATH_ENV in environ
        else "/etc/autoca/autoca.toml"
    )
    config_file = open(config_path, mode="rb")
    config = from_dict(data_class=Config, data=parse_toml(config_file))

    try:
        shared_group = getgrnam(config.shared_group)
    except KeyError:
        error("Shared group '%s' not found, can't continue", config.shared_group)
        exit(1)

    # Checks for config
    for user in set(host.user for host in config.hosts):
        try:
            getgrnam(user)
        except KeyError:
            error("Group '%s' for not found, can't continue", user)
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

    now = datetime.now()

    new_state = state.clone()
    writer = Writer(root_path, shared_group.gr_gid)

    if not new_state.initialized:
        kp = generate_keypair()
        ca = create_ca(kp, config.ca.cn, now, now + timedelta(days=config.ca.duration))
        new_state.set_ca(ca)
        assert new_state.initialized

    old_state = state

    # TODO: We should check if the CA in config is changed and then modify the state

    duration = timedelta(days=config.certificates.duration)
    duration_halved = duration // 2
    start = datetime.fromtimestamp(
        (now.timestamp() // duration_halved.total_seconds())
        * duration_halved.total_seconds()
    )
    mid = start + duration_halved
    end = start + duration
    info(f"Current period start\t{start}")
    info(f"Current period renew\t{mid}")
    info(f"Current period end\t{end}")

    # Add new hosts
    for host in config.hosts:
        # Add certificates for mising or expired hosts
        certs = old_state.certs_by_domain(host.domain)
        add = False
        if len(certs) == 0:
            add = True
            cause = "intial"

        if not add:
            newest_cert = old_state.most_recent(host.domain)
            add = newest_cert.end <= datetime.now() + duration_halved
            cause = "close to expiry"

        if add:
            info("Adding cert for domain %s (cause: %s)", host.domain, cause)  # type: ignore
            kp = generate_keypair()
            cert = create_certificate(
                kp, new_state.ca, host.domain, start, start + duration, host.user
            )
            new_state.add_certificate(cert)

    diff = new_state.diff(old_state)
    debug("Raw diff: %r", diff)

    # Prevent deletions on a normal run
    diff = set(filter(lambda change: change.kind != ChangeKind.delete, diff))
    writer.apply_many(diff)

    info("Saving DB")
    debug("New db: %r", new_state.to_dict())


    if not old_state.initialized or new_state != old_state:
        try:
            new_state.to_file(db_path)
        except:
            import traceback

            error("Could not write db: %r", traceback.format_exc())

    info("Ended autoca")

if __name__ == "__main__":
    main()
