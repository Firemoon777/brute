from datetime import datetime
import os

from sqlalchemy import create_engine, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session


class Base(DeclarativeBase):
    pass


class SSHLoginAttempt(Base):
    __tablename__ = "ssh_login_attempt"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    attempt_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now()
    )
    attempt_number: Mapped[int]

    attacker_ip: Mapped[str]
    attacker_version: Mapped[str]

    dst_ip: Mapped[str]
    dst_port: Mapped[int]

    method: Mapped[str]
    login: Mapped[str] = mapped_column(nullable=True)
    password: Mapped[str] = mapped_column(nullable=True)
    cert: Mapped[str] = mapped_column(nullable=True)


class SSHConnectLog(Base):
    __tablename__ = "ssh_connect_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    docker_id: Mapped[str] = mapped_column(nullable=True)

    attempt_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now()
    )

    attacker_ip: Mapped[str]
    attacker_version: Mapped[str]

    dst_ip: Mapped[str]
    dst_port: Mapped[int]

    login: Mapped[str] = mapped_column(nullable=True)
    password: Mapped[str] = mapped_column(nullable=True)

    command: Mapped[bytes] = mapped_column(nullable=True)
    command_shell: Mapped[str] = mapped_column(nullable=True)

    blob: Mapped[bytes]
    shell: Mapped[str] = mapped_column(nullable=True)


def make_engine(url):
    return create_engine(url)


def make_schema(engine):
    Base.metadata.create_all(engine)


def make_session(engine):
    return Session(engine)

