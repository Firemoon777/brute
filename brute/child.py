import logging
import socket
import time

import paramiko

from brute.enum import Mode
from brute.ssh import HoneypotServer, LogServer


host_key = paramiko.RSAKey(filename="key")


def child_main(client: socket.socket, addr: tuple, mode: Mode):
    logging.info(f"{addr}")

    transport = paramiko.Transport(client)
    transport.set_gss_host(socket.getfqdn(""))
    transport.load_server_moduli()
    transport.add_server_key(host_key)

    if mode == Mode.log:
        server_clz = LogServer
    elif mode == Mode.honeypot:
        server_clz = HoneypotServer
    else:
        raise NotImplementedError()

    logging.info(server_clz)

    server = server_clz()
    transport.start_server(server=server)

    transport.join()
    client.close()
    logging.info("stop")
