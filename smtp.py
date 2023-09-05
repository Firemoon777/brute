import asyncio
import os
import sys
import time
from datetime import datetime

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Session, Envelope

from brute.db import SMTPSendLog, Base, make_engine, Session as SQLSession

engine = make_engine(os.environ["SQLALCHEMY_URL"])
Base.metadata.create_all(engine)


class HoneypotHandler:
    async def handle_DATA(self, server, session: Session, envelope: Envelope):
        with SQLSession(engine) as s:
            s.add(SMTPSendLog(
                attempt_time=datetime.now(),
                attacker_ip=session.peer[0],
                attacker_client=session.host_name,
                msg_from=envelope.mail_from,
                msg_to=envelope.rcpt_tos,
                msg_data=envelope.content,
                msg_data_encoded=envelope.content.decode('utf8', errors='replace')
            ))
            s.commit()

        return '250 Message accepted for delivery'


controller = Controller(
    HoneypotHandler(),
    hostname=sys.argv[1],
    port=int(sys.argv[2]),
    server_hostname="eShop MX",
    server_kwargs=dict(ident="Postfix 3.8.1")
)
controller.start()

print(f"Started on {sys.argv[1]}:{sys.argv[2]}")

try:
    while True:
        time.sleep(50)
except KeyboardInterrupt:
    pass

controller.stop()