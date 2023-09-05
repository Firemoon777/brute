import logging
import os

from brute.enum import Mode

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

import multiprocessing
import signal
import sys
import socket
import time
from typing import List
from .child import child_main
from .db import make_schema, make_engine

running = True


def stop(*args):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def main_loop(s: socket.socket, children: List[multiprocessing.Process], server_addr: tuple, mode: Mode):
    try:
        for proc in children:
            if not proc.is_alive():
                proc.join()
                children.remove(proc)

        client, client_addr = s.accept()
        if client:
            p = multiprocessing.Process(target=child_main, args=(client, client_addr, server_addr, mode))
            p.start()
            children.append(p)

        time.sleep(0.1)
    except BlockingIOError:
        pass


def main(ip: str = "0.0.0.0", port: int = 22, mode: str = "logging"):
    mode_enum = Mode.from_str(mode)
    logging.info(f"Starting in mode {mode_enum.value} on {ip}:{port}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind((ip, int(port)))

    children: List[multiprocessing.Process] = list()

    s.listen()
    try:
        while running:
            main_loop(s, children, (ip, port), mode_enum)
        logging.info(f"Stopped by SIGTERM")
    except KeyboardInterrupt:
        logging.info(f"Keyboard interrupt")

    s.close()
    logging.info("Socket closed")

    for proc in children:
        logging.info(f"Waiting for child with pid = {proc.pid}")
        if proc.is_alive():
            proc.kill()
        proc.join()

    logging.info("exiting...")


if __name__ == "__main__":
    engine = make_engine(os.environ["SQLALCHEMY_URL"])
    make_schema(engine)
    main(*sys.argv[1:])
