import logging

import paramiko
from paramiko.channel import Channel
from paramiko.pkey import PKey

from brute.honeypot import DockerHoneypot, Honeypot


class HoneypotServer(paramiko.ServerInterface):
    honeypot: Honeypot
    client: paramiko.SSHClient
    client_channel: paramiko.Channel

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            self.honeypot = DockerHoneypot()
            self.honeypot.start()

            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            self.client.connect(self.honeypot.get_ip(), username="root", password="root")

            return paramiko.common.OPEN_SUCCEEDED
        return super().check_channel_request(kind, chanid)

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.common.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: PKey) -> int:
        return paramiko.common.AUTH_FAILED

    def check_channel_shell_request(self, channel: Channel) -> bool:
        if self.client_channel:
            return True
        return False

    def check_channel_exec_request(self, channel: Channel, command: bytes) -> bool:
        self.client_channel.exec_command(command)
        channel.sendall(self.client_channel.recv())
        return True

    def check_channel_env_request(self, channel: Channel, name: bytes, value: bytes) -> bool:
        self.client_channel.set_environment_variable(name, value)
        return True

    def check_channel_pty_request(
        self, channel: Channel, term: bytes, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes
    ) -> bool:
        logging.info(f"Requested PTY {term=}, {width}x{height}")
        self.client_channel = self.client.invoke_shell(term.decode(errors="ignore"), width, height, pixelwidth, pixelheight)
        return self.client_channel is not None
