from sqlalchemy import Boolean, CheckConstraint, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAtMixin
from app.models.enums import PrivilegeLevel


class Host(CreatedAtMixin, Base):
    __tablename__ = "hosts"
    __table_args__ = (CheckConstraint("criticality BETWEEN 1 AND 5", name="criticality_range"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(128), unique=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True)
    operating_system: Mapped[str] = mapped_column(String(128))
    department: Mapped[str] = mapped_column(String(64))
    # 1 (low value) .. 5 (crown jewel); drives the risk and prediction engines.
    criticality: Mapped[int] = mapped_column(Integer)
    role: Mapped[str | None] = mapped_column(String(64))
    network_zone: Mapped[str | None] = mapped_column(String(32))

    def __repr__(self) -> str:
        return f"<Host {self.hostname} {self.ip_address}>"


class User(CreatedAtMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(128))
    department: Mapped[str | None] = mapped_column(String(64))
    privilege_level: Mapped[str] = mapped_column(String(32), default=PrivilegeLevel.STANDARD)
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False)

    def __repr__(self) -> str:
        return f"<User {self.username}>"
