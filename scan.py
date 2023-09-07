import json
import os
import socket
import sys
from collections import defaultdict
from datetime import datetime, timedelta

import scapy.packet
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from sqlalchemy.orm import Session

from brute.db import make_engine, Base, TCPScanLog


engine = make_engine(os.environ["SQLALCHEMY_URL"])
Base.metadata.create_all(engine)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

bucket = list()
last_flush = datetime.now()

while True:
    data = s.recv(65536)

    p = IP(data)
    if p.dst != sys.argv[1]:
        continue

    tcp: TCP = p.getlayer(TCP)

    if tcp.flags != 0x2:
        continue

    bucket.append(TCPScanLog(
        attempt_time=datetime.now(),
        attacker_ip=p.src,
        dst_port=tcp.dport
    ))

    if last_flush < datetime.now():
        with Session(engine) as sql:
            sql.add_all(bucket)
            sql.commit()

            print(f"{datetime.now()} Flushed {len(bucket)} entries")
            last_flush = datetime.now() + timedelta(seconds=10)
            bucket.clear()
