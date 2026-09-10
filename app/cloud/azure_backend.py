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
# PROJECT CONFIGURATION
# =========================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)

ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)


if ENV_FILE.exists():

    load_dotenv(
        dotenv_path=str(
            ENV_FILE
        )
    )


# =========================================================
# AZURE CONFIG
# =========================================================

AZURE_SUBSCRIPTION_NAME = os.getenv(
    "AZURE_SUBSCRIPTION_NAME",
    "Azure for Students",
)

AZURE_RESOURCE_GROUP = os.getenv(
    "AZURE_RESOURCE_GROUP"
)

AZURE_STORAGE_ACCOUNT = os.getenv(
    "AZURE_STORAGE_ACCOUNT"
)

AZURE_LOCATION = os.getenv(
    "AZURE_LOCATION"
)


# =========================================================
# LAZY GLOBAL CLIENTS
# =========================================================

_credential = None

_subscription = None

_storage_client = None

_monitor_client = None


# =========================================================
# HELPERS
# =========================================================

def enum_value(
    value,
):
    """
    Convert Azure SDK enum values into simple strings.
    """

    if value is None:

        return None

    return getattr(
        value,
        "value",
        str(value),
    )


def subscription_is_enabled(
    subscription,
):
    """
    Determine whether an Azure subscription is enabled.
    """

    state = enum_value(
        subscription.state
    )

    return (
        str(state)
        .strip()
        .lower()
        == "enabled"
    )


# =========================================================
# CREDENTIAL
# =========================================================

def get_azure_credential():
    """
    Authenticate through the user's browser.

    NEXUS does not store:
        - Azure passwords
        - access tokens
        - client secrets
        - storage account keys
    """

    global _credential


    if _credential is None:

        _credential = (
            InteractiveBrowserCredential()
        )


    return _credential


# =========================================================
# SUBSCRIPTION
# =========================================================

def get_azure_subscription():
    """
    Find the configured Azure subscription.

    Subscription IDs are intentionally kept internal
    and are not returned by NEXUS APIs.
    """

    global _subscription


    if _subscription is not None:

        return _subscription


    credential = (
        get_azure_credential()
    )


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
            "No Azure subscriptions "
            "are available."
        )


    # -----------------------------------------------------
    # Prefer explicitly configured subscription
    # -----------------------------------------------------

    selected = next(
        (
            subscription

            for subscription
            in subscriptions

            if (
                subscription.display_name
                == AZURE_SUBSCRIPTION_NAME

                and
                subscription_is_enabled(
                    subscription
                )
            )
        ),
        None,
    )


    # -----------------------------------------------------
    # Fallback to first enabled subscription
    # -----------------------------------------------------

    if selected is None:

        selected = next(
            (
                subscription

                for subscription
                in subscriptions

                if subscription_is_enabled(
                    subscription
                )
            ),
            None,
        )


    if selected is None:

        raise RuntimeError(
            "No enabled Azure "
            "subscription was found."
        )


    _subscription = selected


    return _subscription


# =========================================================
# AZURE CLIENTS
# =========================================================

def get_storage_client():

    global _storage_client


    if _storage_client is None:

        subscription = (
            get_azure_subscription()
        )

        _storage_client = (
            StorageManagementClient(

                get_azure_credential(),

                subscription.subscription_id,
            )
        )


    return _storage_client


def get_monitor_client():

    global _monitor_client


    if _monitor_client is None:

        subscription = (
            get_azure_subscription()
        )

        _monitor_client = (
            MonitorManagementClient(

                get_azure_credential(),

                subscription.subscription_id,
            )
        )


    return _monitor_client


# =========================================================
# CONFIG VALIDATION
# =========================================================

def validate_azure_configuration():

    missing = []


    if not AZURE_RESOURCE_GROUP:

        missing.append(
            "AZURE_RESOURCE_GROUP"
        )


    if not AZURE_STORAGE_ACCOUNT:

        missing.append(
            "AZURE_STORAGE_ACCOUNT"
        )


    if missing:

        raise RuntimeError(
            "Missing Azure configuration: "
            + ", ".join(
                missing
            )
        )


# =========================================================
# STORAGE RESOURCE
# =========================================================

def get_configured_storage_account():
    """
    Retrieve the real Azure Storage account configured
    for the NEXUS sandbox.
    """

    validate_azure_configuration()


    storage_client = (
        get_storage_client()
    )


    return (
        storage_client
        .storage_accounts
        .get_properties(

            resource_group_name=
                AZURE_RESOURCE_GROUP,

            account_name=
                AZURE_STORAGE_ACCOUNT,
        )
    )


# =========================================================
# AZURE CONNECTION STATUS
# =========================================================

def get_azure_status():
    """
    Verify that NEXUS can authenticate to Azure and
    access the configured storage account.
    """

    try:

        subscription = (
            get_azure_subscription()
        )


        account = (
            get_configured_storage_account()
        )


        return {
            "success":
                True,

            "connected":
                True,

            "backend":
                "AZURE",

            "subscription":
                subscription.display_name,

            "subscription_state":
                enum_value(
                    subscription.state
                ),

            "resource_group":
                AZURE_RESOURCE_GROUP,

            "resource":
                account.name,

            "location":
                account.location,

            "sku":
                enum_value(
                    account.sku.name
                ),

            "kind":
                enum_value(
                    account.kind
                ),
        }


    except Exception as error:

        return {
            "success":
                False,

            "connected":
                False,

            "backend":
                "AZURE",

            "error_type":
                type(error).__name__,

            "message": (
                "NEXUS could not establish "
                "the configured Azure "
                "management connection."
            ),
        }


# =========================================================
# REAL AZURE STORAGE — GET PROPERTIES
# =========================================================

def azure_get_storage_properties(
    storage_account: str,
):
    """
    Perform a REAL Azure Storage management API call.

    Only the configured NEXUS sandbox storage account
    can be inspected.
    """

    validate_azure_configuration()


    # -----------------------------------------------------
    # RESOURCE BINDING
    # -----------------------------------------------------

    if (
        storage_account
        != AZURE_STORAGE_ACCOUNT
    ):

        raise PermissionError(
            "Requested Azure Storage account "
            "is outside the configured "
            "NEXUS sandbox."
        )


    account = (
        get_configured_storage_account()
    )


    return {
        "service":
            "AzureStorage",

        "action":
            "GetProperties",

        "resource":
            account.name,

        "message": (
            "Real Azure Storage account "
            f"{account.name} was inspected "
            "successfully."
        ),

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "backend":
            "AZURE",

        "azure_data": {

            "location":
                account.location,

            "sku":
                enum_value(
                    account.sku.name
                ),

            "kind":
                enum_value(
                    account.kind
                ),

            "https_only":
                account.enable_https_traffic_only,

            "public_network_access":
                enum_value(
                    account.public_network_access
                ),
        },
    }


# =========================================================
# REAL AZURE MONITOR — STORAGE TRANSACTIONS
# =========================================================

def azure_get_storage_transactions(
    storage_account: str,
):
    """
    Retrieve REAL Azure Monitor transaction metrics
    for the configured Storage Account.
    """

    validate_azure_configuration()


    # -----------------------------------------------------
    # RESOURCE BINDING
    # -----------------------------------------------------

    if (
        storage_account
        != AZURE_STORAGE_ACCOUNT
    ):

        raise PermissionError(
            "Requested Azure Storage account "
            "is outside the configured "
            "NEXUS sandbox."
        )


    account = (
        get_configured_storage_account()
    )


    monitor_client = (
        get_monitor_client()
    )


    # -----------------------------------------------------
    # TIME RANGE
    # -----------------------------------------------------

    end_time = datetime.now(
        timezone.utc
    )


    start_time = (
        end_time
        - timedelta(
            minutes=30
        )
    )


    # Azure Monitor expects a clean UTC ISO-8601 format.

    start_text = (
        start_time.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )


    end_text = (
        end_time.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )


    timespan = (
        f"{start_text}/{end_text}"
    )


    # -----------------------------------------------------
    # REAL AZURE MONITOR API
    # -----------------------------------------------------

    metrics = (
        monitor_client
        .metrics
        .list(

            resource_uri=
                account.id,

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


    datapoints = []


    for metric in metrics.value:

        for series in metric.timeseries:

            for point in series.data:

                datapoints.append(
                    {
                        "timestamp": (
                            point.time_stamp
                            .isoformat()

                            if point.time_stamp

                            else None
                        ),

                        "total":
                            point.total,
                    }
                )


    # -----------------------------------------------------
    # MOST RECENT VALUE
    # -----------------------------------------------------

    latest_total = None


    valid_points = [
        point

        for point in datapoints

        if point["total"]
        is not None
    ]


    if valid_points:

        latest_total = (
            valid_points[-1][
                "total"
            ]
        )


    if latest_total is None:

        message = (
            "Real Azure Monitor request "
            "succeeded, but no recent "
            "transaction datapoint "
            "was available."
        )

    else:

        message = (
            "Real Azure Monitor "
            "storage transactions: "
            f"{latest_total}."
        )


    return {
        "service":
            "AzureMonitor",

        "action":
            "GetStorageTransactions",

        "resource":
            account.name,

        "message":
            message,

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "backend":
            "AZURE",

        "azure_data": {

            "metric":
                "Transactions",

            "aggregation":
                "Total",

            "latest_total":
                latest_total,

            "window_minutes":
                30,

            "recent_datapoints":
                datapoints[-5:],
        },
    }


# =========================================================
# REAL AZURE TOOL ALLOWLIST
# =========================================================

REAL_AZURE_TOOLS = {
    "inspect_azure_storage",
    "read_azure_monitor",
}


# =========================================================
# APPROVED AZURE EXECUTOR
# =========================================================

def execute_azure_approved_request(
    request: dict,
):
    """
    Execute ONLY explicitly approved real Azure tools.

    REAL:
        Azure Storage account inspection
        Azure Monitor metrics

    DELIBERATELY NOT IMPLEMENTED:
        Azure Key Vault secret retrieval
        sensitive Blob data access
        external exfiltration

    This acts as an additional defense-in-depth layer.
    """

    tool_name = request.get(
        "tool_name"
    )


    if (
        tool_name
        not in REAL_AZURE_TOOLS
    ):

        return None


    arguments = request.get(
        "arguments",
        {},
    )


    if (
        tool_name
        == "inspect_azure_storage"
    ):

        return (
            azure_get_storage_properties(
                arguments[
                    "storage_account"
                ]
            )
        )


    if (
        tool_name
        == "read_azure_monitor"
    ):

        return (
            azure_get_storage_transactions(
                arguments[
                    "storage_account"
                ]
            )
        )


    return None