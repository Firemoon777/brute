import asyncio
import os
import sys
from datetime import datetime

import telnetlib3
from sqlalchemy.orm import Session
from telnetlib3 import TelnetReader, TelnetWriter

from brute.db import SSHLoginAttempt, make_engine


engine = make_engine(os.environ["SQLALCHEMY_URL"])


async def ubuntu(reader: TelnetReader, writer: TelnetWriter):
    login = writer.protocol.get_extra_info('USER', "")
    attacker_ip = writer.protocol.get_extra_info("peername")[0]
    writer.write('\r\nUbuntu 22.04 LTS')

    print(f"[{attacker_ip}] {writer.protocol._extra}")
    if not login:
        writer.write('\r\nTuring login: ')
        inp = await reader.read(1)
        while inp and inp != "\r":
            login += inp
            writer.write(inp)
            inp = await reader.read(1)

        if not inp:
            writer.close()
            print("pre stop")
            return

    writer.write("\r\nPassword: ")
    password = (await reader.readline()).strip()

    with Session(engine) as session:
        session.add(SSHLoginAttempt(
            attempt_time=datetime.now(),
            attempt_number=1,
            attacker_ip=attacker_ip,
            dst_ip=sys.argv[1],
            dst_port=int(sys.argv[2]),
            method="password",
            login=login,
            password=password,
            attacker_version="telnet"
        ))
        session.commit()
    print(f"[{attacker_ip}] payload: {login}:{password}")

    writer.write("\r\n")
    await asyncio.sleep(3)

    writer.write("\r\nLogin incorrect\r\n")
    writer.close()
    print("stop")


async def shell(reader: TelnetReader, writer: TelnetWriter):
    attacker_ip = writer.protocol.get_extra_info("peername")[0]
    writer.write("> ")

    payload = ""
    try:
        inp = await reader.read(1)
        while inp:
            payload += inp
            writer.write(inp)
            inp = await reader.read(1)
    except Exception as e:
        print(f"[{attacker_ip}] exception: {e}")

    print(f"[{attacker_ip}] payload: {payload}")

loop = asyncio.get_event_loop()
coro = telnetlib3.create_server(host=sys.argv[1], port=int(sys.argv[2]), shell=ubuntu)
server = loop.run_until_complete(coro)
loop.run_until_complete(server.wait_closed())
