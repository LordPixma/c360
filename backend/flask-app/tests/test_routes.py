def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_tenants_crud(client):
    # Initially empty
    r = client.get("/api/tenants")
    assert r.status_code == 200
    assert r.get_json() == []

    # Create
    r = client.post("/api/tenants", json={"name": "Acme"})
    assert r.status_code == 201
    tid = r.get_json()["tenant_id"]
    assert tid

    # Get by id
    r = client.get(f"/api/tenants/{tid}")
    assert r.status_code == 200
    assert r.get_json()["tenant_id"] == tid

    # Patch
    r = client.patch(f"/api/tenants/{tid}", json={"name": "Acme Updated"})
    assert r.status_code == 200
    assert r.get_json()["name"] == "Acme Updated"

    # List again
    r = client.get("/api/tenants")
    data = r.get_json()
    assert any(t["tenant_id"] == tid for t in data)

    # Delete
    r = client.delete(f"/api/tenants/{tid}")
    assert r.status_code == 200
    r = client.get(f"/api/tenants/{tid}")
    assert r.status_code == 404


def test_users_under_tenant(client):
    # Create tenant
    tr = client.post("/api/tenants", json={"name": "Acme"})
    tid = tr.get_json()["tenant_id"]

    # Initially empty
    r = client.get(f"/api/tenants/{tid}/users")
    assert r.status_code == 200
    assert r.get_json() == []

    # Create user
    r = client.post(f"/api/tenants/{tid}/users", json={"email": "a@acme.com", "role": "admin"})
    assert r.status_code == 201
    user = r.get_json()
    assert user["email"] == "a@acme.com"
    assert user["role"] == "admin"

    # List now returns the user
    r = client.get(f"/api/tenants/{tid}/users")
    users = r.get_json()
    assert len(users) == 1
    assert users[0]["email"] == "a@acme.com"

    # Get one
    uid = users[0]["user_id"]
    r = client.get(f"/api/tenants/{tid}/users/{uid}")
    assert r.status_code == 200

    # Patch
    r = client.patch(f"/api/tenants/{tid}/users/{uid}", json={"role": "member"})
    assert r.status_code == 200
    assert r.get_json()["role"] == "member"

    # Delete
    r = client.delete(f"/api/tenants/{tid}/users/{uid}")
    assert r.status_code == 200
    r = client.get(f"/api/tenants/{tid}/users/{uid}")
    assert r.status_code == 404
