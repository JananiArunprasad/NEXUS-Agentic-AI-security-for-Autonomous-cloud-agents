import os

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from pathlib import Path

from dotenv import load_dotenv

from azure.identity import (
    InteractiveBrowserCredential,
)

from azure.mgmt.resource.subscriptions import (
    SubscriptionClient,
)

from azure.mgmt.storage import (
    StorageManagementClient,
)

from azure.mgmt.monitor import (
    MonitorManagementClient,
)


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


RESOURCE_GROUP = os.getenv(
    "AZURE_RESOURCE_GROUP"
)

STORAGE_ACCOUNT = os.getenv(
    "AZURE_STORAGE_ACCOUNT"
)


if not RESOURCE_GROUP:

    raise RuntimeError(
        "AZURE_RESOURCE_GROUP "
        "is missing from .env"
    )


if not STORAGE_ACCOUNT:

    raise RuntimeError(
        "AZURE_STORAGE_ACCOUNT "
        "is missing from .env"
    )


print(
    "RESOURCE GROUP:",
    RESOURCE_GROUP
)

print(
    "STORAGE ACCOUNT:",
    STORAGE_ACCOUNT
)


# =========================================================
# AUTHENTICATION
# =========================================================

credential = (
    InteractiveBrowserCredential()
)


# =========================================================
# FIND SUBSCRIPTION
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


subscription = next(
    (
        item
        for item in subscriptions

        if item.display_name
        == "Azure for Students"
    ),

    subscriptions[0],
)


subscription_id = (
    subscription.subscription_id
)


print(
    "SUBSCRIPTION:",
    subscription.display_name
)

print(
    "STATE:",
    subscription.state
)


# =========================================================
# AZURE CLIENTS
# =========================================================

storage_client = (
    StorageManagementClient(
        credential,
        subscription_id,
    )
)


monitor_client = (
    MonitorManagementClient(
        credential,
        subscription_id,
    )
)


# =========================================================
# GET REAL STORAGE RESOURCE
# =========================================================

account = (
    storage_client
    .storage_accounts
    .get_properties(
        resource_group_name=
            RESOURCE_GROUP,

        account_name=
            STORAGE_ACCOUNT,
    )
)


resource_id = (
    account.id
)


print(
    "RESOURCE TYPE:",
    account.type
)


# =========================================================
# METRIC TIME RANGE
# =========================================================

end_time = datetime.now(
    timezone.utc
)


start_time = (
    end_time
    - timedelta(
        minutes=30
    )
)


# =========================================================
# AZURE MONITOR ISO-8601 TIME RANGE
# =========================================================

start_text = start_time.strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)

end_text = end_time.strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)

timespan = (
    f"{start_text}/{end_text}"
)

print(
    "TIMESPAN:",
    timespan
)


# =========================================================
# REAL AZURE MONITOR API CALL
# =========================================================

metrics = (
    monitor_client
    .metrics
    .list(
        resource_uri=
            resource_id,

        timespan=
            timespan,

        interval=
            "PT5M",

        metricnames=
            "Transactions",

        aggregation=
            "Total",
    )
)


# =========================================================
# RESULTS
# =========================================================

print()
print(
    "=================================="
)

print(
    "REAL AZURE MONITOR OK"
)

print(
    "=================================="
)


if not metrics.value:

    print(
        "Monitor request succeeded, "
        "but no metric objects were returned."
    )


for metric in metrics.value:

    print(
        "METRIC:",
        metric.name.value
    )


    datapoints = []


    for series in metric.timeseries:

        datapoints.extend(
            series.data
        )


    if not datapoints:

        print(
            "No recent datapoints yet."
        )

        continue


    for point in datapoints[-5:]:

        print(
            "TIME:",
            point.time_stamp,
            "| TOTAL:",
            point.total,
        )