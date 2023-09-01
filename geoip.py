import os
import csv

import sqlalchemy.dialects.postgresql
from sqlalchemy import create_engine, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session


class Base(DeclarativeBase):
    pass


class GeoIP(Base):
    __tablename__ = "geoip"

    network: Mapped[str] = mapped_column(sqlalchemy.dialects.postgresql.INET(), primary_key=True)
    geoname_id: Mapped[int] = mapped_column(nullable=True)
    registered_country_geoname_id: Mapped[int] = mapped_column(nullable=True)
    represented_country_geoname_id: Mapped[int] = mapped_column(nullable=True)
    is_anonymous_proxy: Mapped[bool] = mapped_column(nullable=True)
    is_satellite_provider: Mapped[bool] = mapped_column(nullable=True)
    postal_code: Mapped[str] = mapped_column(nullable=True)
    latitude: Mapped[float] = mapped_column(nullable=True)
    longitude: Mapped[float] = mapped_column(nullable=True)
    accuracy_radius: Mapped[float] = mapped_column(nullable=True)


engine = create_engine(os.environ["SQLALCHEMY_URL"])
Base.metadata.create_all(engine)

session = Session(engine)
session.begin()

with open("GeoLite2-City-Blocks-IPv4.csv", "r") as f:
    reader = csv.DictReader(f)
    for i, line in enumerate(reader):
        if i % 100_000 == 0:
            print(f">>> {i} / 3782064")
            session.commit()
        session.add(GeoIP(
            network=line["network"],
            geoname_id=int(line["geoname_id"]) if line["geoname_id"] else None,
            registered_country_geoname_id=int(line["registered_country_geoname_id"]) if line["registered_country_geoname_id"] else None,
            represented_country_geoname_id=int(line["represented_country_geoname_id"]) if line["represented_country_geoname_id"] else None,
            is_anonymous_proxy=False if line["is_anonymous_proxy"] == "0" else True,
            is_satellite_provider=False if line["is_satellite_provider"] == "0" else True,
            postal_code=line["postal_code"] if line["postal_code"] else None,
            latitude=float(line["latitude"]) if line["latitude"] else None,
            longitude=float(line["longitude"]) if line["longitude"] else None,
            accuracy_radius=float(line["accuracy_radius"]) if line["accuracy_radius"] else None
        ))

session.commit()
