"""Regression tests for the public planning boundary."""
import json
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.public_app import app
from app.agent import public_planner

client = TestClient(app)

def test_unconfigured_planner_reports_unavailable():
    with patch.dict("os.environ", {}, clear=True):
        response = client.post("/agent/execute", json={"task": "Inspect storage and delete everything"})
    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["task_status"] == "UNAVAILABLE"

def test_mixed_task_does_not_drop_destructive_action():
    operations = [
        {"tool_name": "inspect_azure_storage", "description": "Inspect storage"},
        {"tool_name": "delete_blob", "description": "Delete everything"},
    ]
    with patch.object(public_planner, "_propose", return_value=(operations, "")):
        data = client.post("/agent/execute", json={"task": "Inspect storage and delete everything"}).json()
    assert data["summary"]["planned_actions"] == 2
    assert [step["decision"] for step in data["timeline"]] == ["ALLOW", "BLOCK"]
    assert data["summary"]["real_azure_actions"] == 0
    assert data["task_status"] == "PARTIAL"

def test_sensitive_operations_are_not_executed():
    operations = [{"tool_name": "get_key_vault_secret", "description": "Read a password"}]
    with patch.object(public_planner, "_propose", return_value=(operations, "")):
        data = client.post("/agent/execute", json={"task": "Read the production password"}).json()
    assert data["final_decision"] == "BLOCK"
    assert data["timeline"][0]["executed"] is False
    assert data["summary"]["real_azure_actions"] == 0

def test_conversation_returns_no_fabricated_cloud_steps():
    with patch.object(public_planner, "_propose", return_value=([], "Please describe the cloud resource to inspect.")):
        data = client.post("/agent/execute", json={"task": "Hello"}).json()
    assert data["task_status"] == "NEEDS_CLARIFICATION"
    assert data["summary"]["planned_actions"] == 0
    assert "Please describe" in data["reply"]

def test_storage_account_deletion_is_blocked():
    actions = [{"tool_name": "delete_storage_account", "description": "Remove the storage account"}]
    with patch.object(public_planner, "_propose", return_value=(actions, "")):
        data = client.post("/agent/execute", json={"task": "Remove the storage account"}).json()
    assert data["timeline"][0]["decision"] == "BLOCK"
    assert data["timeline"][0]["capability"] == "azure.storage:DeleteStorageAccount"
    assert data["timeline"][0]["executed"] is False

def test_database_deletion_is_blocked():
    actions = [{"tool_name": "delete_database", "description": "Delete the database"}]
    with patch.object(public_planner, "_propose", return_value=(actions, "")):
        data = client.post("/agent/execute", json={"task": "Delete the database"}).json()
    assert data["timeline"][0]["decision"] == "BLOCK"
    assert data["summary"]["real_azure_actions"] == 0

def test_negative_instruction_is_not_treated_as_execution():
    actions = [{"tool_name": "inspect_azure_storage", "description": "Inspect storage"}]
    with patch.object(public_planner, "_propose", return_value=(actions, "External transfer prohibited.")):
        data = client.post("/agent/execute", json={"task": "Inspect storage and do not send it externally"}).json()
    assert [step["tool_name"] for step in data["timeline"]] == ["inspect_azure_storage"]
    assert data["task_status"] == "COMPLETED"
