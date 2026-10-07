from __future__ import annotations
from dataclasses import dataclass
from backend_bryan.auth.models import AuthPrincipal
from backend_bryan.auth.service import AuthenticationService

@dataclass
class Config:
    enabled: bool = True
    jwt_secret: str = "x" * 32
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

class Store:
    def __init__(self): self.users={"u1":{"id":"u1","username":"admin","role":"admin","disabled":False},"u2":{"id":"u2","username":"analyst","role":"analyst","disabled":False}}
    def principal_by_id(self, uid):
        u=self.users.get(uid)
        return None if not u or u["disabled"] else AuthPrincipal(uid,u["username"],True,u["role"])
    def list_users(self): return list(self.users.values())
    def create_user(self, username,password,role,email=""):
        assert len(password)>=8; u={"id":"u3","username":username,"role":role,"disabled":False,"email":email}; self.users["u3"]=u; return u
    def update_user(self, uid, *, role=None, disabled=None):
        u=self.users.get(uid)
        if not u:return None
        if role is not None:u["role"]=role
        if disabled is not None:u["disabled"]=disabled
        return u
    def change_password(self,uid,current,new): return current=="old-password" and len(new)>=8
    def close(self): pass

def test_admin_management_and_self_disable_guard():
    svc=AuthenticationService(Config(),Store())
    admin=AuthPrincipal("u1","admin",True,"admin")
    assert len(svc.list_users(admin))==2
    assert svc.create_user(admin,"new","password123","read_only")["role"]=="read_only"
    assert svc.update_user(admin,"u2",disabled=True)["disabled"] is True
    try: svc.update_user(admin,"u1",disabled=True)
    except ValueError: pass
    else: raise AssertionError("self-disable must be rejected")

def test_non_admin_cannot_manage_users_and_password_requires_current_password():
    svc=AuthenticationService(Config(),Store())
    analyst=AuthPrincipal("u2","analyst",True,"analyst")
    try: svc.list_users(analyst)
    except PermissionError: pass
    else: raise AssertionError("admin gate missing")
    try: svc.change_password(analyst,"wrong","new-password")
    except PermissionError: pass
    else: raise AssertionError("current password must be verified")
    svc.change_password(analyst,"old-password","new-password")
