from enum import Enum


class Mode(Enum):
    log = "LOGGING"
    honeypot = "HONEYPOT"

    @staticmethod
    def from_str(d: str):
        data = d.upper()

        if data == Mode.log.value:
            return Mode.log

        if data == Mode.honeypot.value:
            return Mode.honeypot

        raise RuntimeError(f"No mode for {data}")