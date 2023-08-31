import logging
import time

import paramiko
from paramiko.channel import Channel
from paramiko.pkey import PKey


class LogServer(paramiko.ServerInterface):

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return super().check_channel_request(kind, chanid)

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        logging.info(f"Password {username}:{password}")
        time.sleep(3)
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: PKey) -> int:
        return paramiko.common.AUTH_FAILED

