from __future__ import annotations
from datetime import datetime
from .extensions import db


class Tenant(db.Model):
    __tablename__ = "tenants"

    tenant_id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    users = db.relationship("User", back_populates="tenant", cascade="all, delete-orphan")


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.String(36), primary_key=True)
    tenant_id = db.Column(db.String(36), db.ForeignKey("tenants.tenant_id"), nullable=False, index=True)
    email = db.Column(db.String(320), nullable=False, unique=True, index=True)
    role = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tenant = db.relationship("Tenant", back_populates="users")
