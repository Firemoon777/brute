import datetime
import logging
import time

import paramiko
from paramiko.channel import Channel
from paramiko.pkey import PKey

from ..db import SSHLoginAttempt


class LogServer(paramiko.ServerInterface):

    output: list
    attempt: int

    def __init__(self, server_addr, client_addr, transport, **kwargs):
        self.output = list()
        self.attempt = 0
        self.server_addr = server_addr
        self.client_addr = client_addr
        self.transport = transport

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return super().check_channel_request(kind, chanid)

    def get_allowed_auths(self, username: str) -> str:
        self.output.append(SSHLoginAttempt(
            attempt_time=datetime.datetime.now(),
            attempt_number=self.attempt,
            attacker_ip=self.client_addr[0],
            dst_ip=self.server_addr[0],
            dst_port=self.server_addr[1],
            method="connect",
            attacker_version=self.transport.remote_version
        ))
        return "password,publickey"

    def check_auth_none(self, username: str) -> int:
        self.output.append(SSHLoginAttempt(
            attempt_time=datetime.datetime.now(),
            attempt_number=self.attempt,
            attacker_ip=self.client_addr[0],
            dst_ip=self.server_addr[0],
            dst_port=self.server_addr[1],
            method="none",
            login=username,
            attacker_version=self.transport.remote_version
        ))
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        self.attempt += 1

        self.output.append(SSHLoginAttempt(
            attempt_time=datetime.datetime.now(),
            attempt_number=self.attempt,
            attacker_ip=self.client_addr[0],
            dst_ip=self.server_addr[0],
            dst_port=self.server_addr[1],
            method="password",
            login=username,
            password=password,
            attacker_version=self.transport.remote_version
        ))
        time.sleep(3)
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: PKey) -> int:
        self.attempt += 1

        self.output.append(SSHLoginAttempt(
            attempt_time=datetime.datetime.now(),
            attempt_number=self.attempt,
            attacker_ip=self.client_addr[0],
            dst_ip=self.server_addr[0],
            dst_port=self.server_addr[1],
            method="publickey",
            login=username,
            cert=key.get_fingerprint().hex(":", 2),
            attacker_version=self.transport.remote_version
        ))
        return paramiko.common.AUTH_FAILED

