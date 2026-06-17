"""FastAPI routes that front the support service.

Demonstrates:
- API endpoint detection (FastAPI routes, method + path + auth style)
- Risk indicator: object-id in path (BOLA candidate) on the /customers routes
"""
from __future__ import annotations

from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/orders/{order_id}")
def get_order(order_id: str) -> dict:
    return {"id": order_id}


@app.get("/customers/{customer_id}")
def get_customer(customer_id: str) -> dict:
    return {"id": customer_id}


@app.patch("/customers/{customer_id}")
def update_customer(customer_id: str, address: str) -> dict:
    return {"id": customer_id, "address": address}
