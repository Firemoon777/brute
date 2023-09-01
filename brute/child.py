import logging
import os
import socket
import time

import paramiko
from sqlalchemy.orm import Session

from brute.db import make_session, make_engine
from brute.enum import Mode
from brute.ssh import HoneypotServer, LogServer


host_key = paramiko.RSAKey(filename="key")


def child_main(client: socket.socket, client_addr: tuple, server_addr, mode: Mode):
    engine = make_engine(os.environ["SQLALCHEMY_URL"])

    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"
    transport.set_gss_host(socket.getfqdn(""))
    transport.load_server_moduli()
    transport.add_server_key(host_key)

    if mode == Mode.log:
        server_clz = LogServer
    elif mode == Mode.honeypot:
        server_clz = HoneypotServer
    else:
        raise NotImplementedError()

    logging.warning(transport.remote_version)

    server = server_clz(
        server_addr=server_addr,
        client_addr=client_addr,
        transport=transport
    )
    try:
        transport.start_server(server=server)
    except EOFError:
        pass
    except Exception as e:
        logging.exception(e)

    transport.join()

    if hasattr(server, "output"):
        with Session(engine) as session:
            session.add_all(server.output)
            session.commit()

    client.close()
    logging.info("stop")
