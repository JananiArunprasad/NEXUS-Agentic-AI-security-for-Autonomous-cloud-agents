from app.evaluation.evaluator import (
    run_evaluation,
    read_latest_evaluation,
)


def test_evaluation_runs():

    result = run_evaluation()

    assert result["success"] is True

    assert "metrics" in result

    assert "scenarios" in result


def test_evaluation_contains_all_core_scenarios():

    result = run_evaluation()

    assert (
        result["metrics"][
            "scenario_count"
        ]
        == 12
    )

    assert (
        result["metrics"][
            "benign_scenarios"
        ]
        == 6
    )

    assert (
        result["metrics"][
            "malicious_scenarios"
        ]
        == 6
    )


def test_metrics_are_valid_ranges():

    result = run_evaluation()

    metrics = result["metrics"]

    percentage_metrics = [
        "attack_blocking_rate",
        "benign_task_success_rate",
        "false_positive_rate",
        "false_negative_rate",
        "precision",
        "recall",
        "f1_score",
        "legitimate_recovery_success_rate",
    ]

    for metric in percentage_metrics:

        assert (
            0.0
            <= metrics[metric]
            <= 1.0
        )


def test_latest_report_can_be_read():

    run_evaluation()

    result = (
        read_latest_evaluation()
    )

    assert result["success"] is True

    assert (
        "metrics"
        in result
    )


def test_benign_scenarios_are_not_blocked():

    result = run_evaluation()

    benign_results = [
        scenario
        for scenario in result["scenarios"]
        if scenario["label"] == "BENIGN"
    ]

    for scenario in benign_results:

        assert (
            scenario["classification"]
            == "TN"
        )


def test_known_attack_chain_scenarios_are_interrupted():

    result = run_evaluation()

    malicious_results = [
        scenario
        for scenario in result["scenarios"]
        if scenario["label"]
        == "MALICIOUS"
    ]

    for scenario in malicious_results:

        assert (
            scenario["classification"]
            == "TP"
        )


def test_legitimate_recovery_after_attack_block():

    result = run_evaluation()

    malicious_results = [
        scenario
        for scenario in result["scenarios"]
        if scenario["label"]
        == "MALICIOUS"
    ]

    for scenario in malicious_results:

        if scenario[
            "recovery_tested"
        ]:

            assert (
                scenario[
                    "recovery_success"
                ]
                is True
            )