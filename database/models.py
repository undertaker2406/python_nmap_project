"""SQLAlchemy ORM models."""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Float, ForeignKey,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Target(Base):
    __tablename__ = "targets"

    id          = Column(Integer, primary_key=True)
    ip          = Column(String(45), unique=True, nullable=False, index=True)
    hostname    = Column(String(255))
    mac_address = Column(String(17))
    vendor      = Column(String(255))
    status      = Column(String(16), default="unknown")   # up / down / unknown
    os_family   = Column(String(128))
    os_match    = Column(String(255))
    os_accuracy = Column(Integer)
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="target", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id, "ip": self.ip, "hostname": self.hostname,
            "mac_address": self.mac_address, "vendor": self.vendor,
            "status": self.status, "os_family": self.os_family,
            "os_match": self.os_match, "os_accuracy": self.os_accuracy,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }


class Scan(Base):
    __tablename__ = "scans"

    id          = Column(Integer, primary_key=True)
    target_id   = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_type   = Column(String(32), nullable=False)         # quick/standard/full_tcp/udp/custom
    command     = Column(String(512))
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    status      = Column(String(16), default="running")      # running/completed/failed
    raw_output  = Column(Text)

    target = relationship("Target", back_populates="scans")
    ports  = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    hops   = relationship("TracerouteHop", back_populates="scan", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    id         = Column(Integer, primary_key=True)
    scan_id    = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    target_id  = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    port       = Column(Integer, nullable=False)
    protocol   = Column(String(8), default="tcp")
    state      = Column(String(16))                          # open/closed/filtered
    service    = Column(String(64))
    product    = Column(String(255))
    version    = Column(String(64))
    extra_info = Column(Text)

    scan   = relationship("Scan", back_populates="ports")
    target = relationship("Target", back_populates="ports")

    def to_dict(self):
        return {
            "port": self.port, "protocol": self.protocol, "state": self.state,
            "service": self.service, "product": self.product,
            "version": self.version, "extra_info": self.extra_info,
        }


class TracerouteHop(Base):
    __tablename__ = "traceroute_hops"

    id           = Column(Integer, primary_key=True)
    scan_id      = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    hop_number   = Column(Integer, nullable=False)
    hop_ip       = Column(String(45))
    hop_hostname = Column(String(255))
    rtt          = Column(Float)

    scan = relationship("Scan", back_populates="hops")