import os
from pathlib import Path

from dotenv import load_dotenv

from azure.identity import InteractiveBrowserCredential
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient


# =========================================================
# NEXUS PROJECT ROOT
# =========================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)


# =========================================================
# LOAD .ENV EXPLICITLY
# =========================================================

if not ENV_FILE.exists():

    raise FileNotFoundError(
        f"NEXUS .env file not found at: {ENV_FILE}"
    )


load_dotenv(
    dotenv_path=str(
        ENV_FILE
    )
)


resource_group = os.getenv(
    "AZURE_RESOURCE_GROUP"
)

storage_account = os.getenv(
    "AZURE_STORAGE_ACCOUNT"
)


print(
    "ENV FILE:",
    ENV_FILE
)

print(
    "RESOURCE GROUP:",
    resource_group
)

print(
    "STORAGE ACCOUNT:",
    storage_account
)


# =========================================================
# VALIDATE CONFIGURATION
# =========================================================

if not resource_group:

    raise RuntimeError(
        "AZURE_RESOURCE_GROUP "
        "is missing from .env"
    )


if not storage_account:

    raise RuntimeError(
        "AZURE_STORAGE_ACCOUNT "
        "is missing from .env"
    )


# =========================================================
# AZURE LOGIN
# =========================================================

credential = (
    InteractiveBrowserCredential()
)


# =========================================================
# FIND AZURE SUBSCRIPTION
# =========================================================

subscription_client = (
    SubscriptionClient(
        credential
    )
)


subscriptions = list(
    subscription_client
    .subscriptions
    .list()
)


if not subscriptions:

    raise RuntimeError(
        "No Azure subscriptions found."
    )


# Prefer Azure for Students
subscription = next(
    (
        item
        for item in subscriptions

        if item.display_name
        == "Azure for Students"
    ),

    subscriptions[0],
)


print(
    "SUBSCRIPTION:",
    subscription.display_name
)

print(
    "STATE:",
    subscription.state
)


subscription_id = (
    subscription.subscription_id
)


# =========================================================
# AZURE STORAGE CLIENT
# =========================================================

storage_client = (
    StorageManagementClient(
        credential,
        subscription_id,
    )
)


# =========================================================
# REAL AZURE API CALL
# =========================================================

account = (
    storage_client
    .storage_accounts
    .get_properties(
        resource_group_name=
            resource_group,

        account_name=
            storage_account,
    )
)


# =========================================================
# SUCCESS
# =========================================================

print()
print(
    "=================================="
)

print(
    "REAL AZURE STORAGE OK"
)

print(
    "=================================="
)

print(
    "NAME:",
    account.name
)

print(
    "LOCATION:",
    account.location
)

print(
    "SKU:",
    account.sku.name
)

print(
    "KIND:",
    account.kind
)