import os
import csv
from ipaddress import ip_address, ip_network

import sqlalchemy.dialects.postgresql
from sqlalchemy import create_engine, DateTime, select, distinct
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session


from brute.db import make_engine, make_schema, SSHLoginAttempt, SSHConnectLog, Base, IPEntry, WebLoginAttempt, SMTPSendLog

engine = make_engine(os.environ["SQLALCHEMY_URL"])
Base.metadata.create_all(engine)

session = Session(engine)
session.begin()

exists = select(distinct(IPEntry.ip))

stmt_arr = [
    select(distinct(SSHLoginAttempt.attacker_ip)).where(SSHLoginAttempt.attacker_ip.notin_(exists)),
    select(distinct(SSHConnectLog.attacker_ip)).where(SSHConnectLog.attacker_ip.notin_(exists)),
    select(distinct(WebLoginAttempt.attacker_ip)).where(WebLoginAttempt.attacker_ip.notin_(exists)),
    select(distinct(SMTPSendLog.attacker_ip)).where(SMTPSendLog.attacker_ip.notin_(exists)),
]

to_export = dict()

for stmt in stmt_arr:
    result = session.execute(stmt)
    for entry in result:
        ip = ip_address(entry[0])

        if ip in to_export:
            continue

        to_export[ip] = IPEntry(
            ip=entry[0],
            asn=None,
            as_=None,
            geoname_id=None,
            country_name=None,
            city_name=None,
            latitude=None,
            longitude=None,
            accuracy_radius=None
        )

print("asn")
with open("geolite2/GeoLite2-ASN-Blocks-IPv4.csv") as f:
    reader = csv.DictReader(f)

    for line in reader:
        subnet = line["network"]
        for attacker_ip, entry in to_export.items():
            if attacker_ip in ip_network(subnet):
                entry.as_ = line["autonomous_system_organization"]
                entry.asn = int(line["autonomous_system_number"]) if line["autonomous_system_number"] else None
                print(f"{attacker_ip} -> {line}")

print("city")
with open("geolite2/GeoLite2-City-Blocks-IPv4.csv") as f:
    reader = csv.DictReader(f)

    for line in reader:
        subnet = line["network"]
        for attacker_ip, entry in to_export.items():
            if attacker_ip in ip_network(subnet):
                entry.geoname_id = int(line.get("geoname_id"))
                entry.latitude = float(line["latitude"]) if line["latitude"] else None
                entry.longitude = float(line["longitude"]) if line["longitude"] else None
                entry.accuracy_radius = float(line["accuracy_radius"]) if line["accuracy_radius"] else None
                print(f"{attacker_ip} -> {line}")


print("geoname encoding")
with open("geolite2/GeoLite2-City-Locations-ru.csv") as f:
    reader = csv.DictReader(f)

    for line in reader:
        geoname_id = int(line["geoname_id"])
        for entry in to_export.values():
            if entry.geoname_id is None:
                continue

            if entry.geoname_id == geoname_id:
                entry.country_name = line["country_name"]
                entry.city_name = line["city_name"]


session.add_all(list(to_export.values()))
session.commit()
