import datetime
import logging
import os
import socket
import threading
from io import BytesIO
from threading import Thread

import paramiko
from paramiko.channel import Channel
from paramiko.ssh_exception import SSHException
from sqlalchemy.orm import Session

from brute.db import make_session, make_engine, SSHConnectLog
from brute.enum import Mode
from brute.ssh import HoneypotServer, LogServer


host_key = paramiko.RSAKey(filename="key")


def child_main(client: socket.socket, client_addr: tuple, server_addr: tuple, mode: Mode):
    if mode == Mode.log:
        return child_logging_main(client, client_addr, server_addr)
    elif mode == Mode.honeypot:
        return child_honeypot_main(client, client_addr, server_addr)


def child_logging_main(client: socket.socket, client_addr: tuple, server_addr):
    engine = make_engine(os.environ["SQLALCHEMY_URL"])

    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"
    transport.set_gss_host(socket.getfqdn(""))
    transport.load_server_moduli()
    transport.add_server_key(host_key)

    server = LogServer(
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


def child_honeypot_main(client: socket.socket, client_addr: tuple, server_addr):
    engine = make_engine(os.environ["SQLALCHEMY_URL"])

    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"
    transport.set_gss_host(socket.getfqdn(""))
    transport.load_server_moduli()
    transport.add_server_key(host_key)

    server = HoneypotServer()
    try:
        transport.start_server(server=server)
    except SSHException as e:
        logging.exception(e)
        exit(0)

    server_channel = transport.accept(30)
    if not server_channel:
        logging.info("No channel found")
        exit(0)

    server.event.wait(10)
    if not server.event.is_set():
        server.client.close()
        exit(0)

    channel_closed = threading.Event()

    transfer_data = BytesIO()

    def transfer(_from: Channel, _to: Channel):
        while True:
            data = _from.recv(4096)
            if len(data) == 0:
                channel_closed.set()
                break

            transfer_data.write(data)
            _to.send(data)

    threads = [
        Thread(target=transfer, args=(server_channel, server.client_channel)),
        Thread(target=transfer, args=(server.client_channel, server_channel)),
    ]

    for t in threads:
        t.start()

    logging.info("started")
    remote_version = transport.remote_version

    channel_closed.wait()

    logging.info(f"someone closed socket")

    try:
        server.client_channel.close()
    except:
        pass

    try:
        transport.close()
    except:
        pass

    for t in threads:
        t.join()

    transfer_data.seek(0)
    blob = transfer_data.read()
    with Session(engine) as session:
        session.add(SSHConnectLog(
            docker_id=server.honeypot.container_id,
            attempt_time=datetime.datetime.now(),
            attacker_ip=client_addr[0],
            dst_ip=server_addr[0],
            dst_port=server_addr[1],
            login=server.login,
            password=server.password,
            command=server.command,
            command_shell=server.command.decode("utf8", errors="ignore") if server.command else None,
            attacker_version=remote_version,
            blob=blob,
            shell=blob.decode("utf8", errors="ignore")
        ))
        session.commit()

    logging.info("stop")

