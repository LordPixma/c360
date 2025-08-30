from flask import Blueprint, request, abort
import uuid
from ..extensions import db
from ..models import Tenant, User
from sqlalchemy.exc import IntegrityError
from ..utils import error_response
import re

bp = Blueprint("tenants", __name__)


@bp.get("/tenants")
def list_tenants():
    tenants = Tenant.query.order_by(Tenant.created_at.desc()).limit(100).all()
    return [
        {"tenant_id": t.tenant_id, "name": t.name, "created_at": t.created_at.isoformat()}
        for t in tenants
    ]


@bp.post("/tenants")
def create_tenant():
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    if not name:
        abort(400, description="name is required")
    tenant = Tenant(tenant_id=str(uuid.uuid4()), name=name)
    db.session.add(tenant)
    db.session.commit()
    return {
        "tenant_id": tenant.tenant_id,
        "name": tenant.name,
        "created_at": tenant.created_at.isoformat(),
    }, 201

@bp.get("/tenants/<tenant_id>")
def get_tenant(tenant_id: str):
    t = Tenant.query.filter_by(tenant_id=tenant_id).first()
    if not t:
        abort(404)
    return {"tenant_id": t.tenant_id, "name": t.name, "created_at": t.created_at.isoformat()}


@bp.patch("/tenants/<tenant_id>")
def update_tenant(tenant_id: str):
    t = Tenant.query.filter_by(tenant_id=tenant_id).first()
    if not t:
        abort(404)
    payload = request.get_json(silent=True) or {}
    if "name" in payload and payload["name"]:
        t.name = payload["name"]
    db.session.commit()
    return {"tenant_id": t.tenant_id, "name": t.name, "created_at": t.created_at.isoformat()}


@bp.delete("/tenants/<tenant_id>")
def delete_tenant(tenant_id: str):
    t = Tenant.query.filter_by(tenant_id=tenant_id).first()
    if not t:
        abort(404)
    db.session.delete(t)
    db.session.commit()
    return {"deleted": True}


@bp.get("/tenants/<tenant_id>/users")
def list_users(tenant_id: str):
    users = User.query.filter_by(tenant_id=tenant_id).order_by(User.created_at.desc()).all()
    return [
        {
            "user_id": u.user_id,
            "tenant_id": u.tenant_id,
            "email": u.email,
            "role": u.role,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]


@bp.post("/tenants/<tenant_id>/users")
def create_user(tenant_id: str):
    payload = request.get_json(silent=True) or {}
    email = payload.get("email")
    role = payload.get("role") or "member"
    if not email:
        abort(400, description="email is required")
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        abort(400, description="invalid email")
    if role not in {"admin", "member"}:
        abort(400, description="invalid role")
    # Ensure tenant exists
    if not Tenant.query.get(tenant_id):
        abort(404)
    user = User(user_id=str(uuid.uuid4()), tenant_id=tenant_id, email=email, role=role)
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return error_response("conflict", "email already exists", 409)
    return {
        "user_id": user.user_id,
        "tenant_id": user.tenant_id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
    }, 201


@bp.get("/tenants/<tenant_id>/users/<user_id>")
def get_user(tenant_id: str, user_id: str):
    u = User.query.filter_by(tenant_id=tenant_id, user_id=user_id).first()
    if not u:
        abort(404)
    return {
        "user_id": u.user_id,
        "tenant_id": u.tenant_id,
        "email": u.email,
        "role": u.role,
        "created_at": u.created_at.isoformat(),
    }


@bp.patch("/tenants/<tenant_id>/users/<user_id>")
def update_user(tenant_id: str, user_id: str):
    u = User.query.filter_by(tenant_id=tenant_id, user_id=user_id).first()
    if not u:
        abort(404)
    payload = request.get_json(silent=True) or {}
    if "email" in payload:
        email = payload["email"]
        if email and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            abort(400, description="invalid email")
        if email:
            u.email = email
    if "role" in payload:
        role = payload["role"]
        if role and role not in {"admin", "member"}:
            abort(400, description="invalid role")
        if role:
            u.role = role
    db.session.commit()
    return {
        "user_id": u.user_id,
        "tenant_id": u.tenant_id,
        "email": u.email,
        "role": u.role,
        "created_at": u.created_at.isoformat(),
    }


@bp.delete("/tenants/<tenant_id>/users/<user_id>")
def delete_user(tenant_id: str, user_id: str):
    u = User.query.filter_by(tenant_id=tenant_id, user_id=user_id).first()
    if not u:
        abort(404)
    db.session.delete(u)
    db.session.commit()
    return {"deleted": True}
