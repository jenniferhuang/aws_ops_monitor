from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from aws_ops_monitor.collectors.aws_lightsail import (
    LightsailCollector,
    _default_client_factory,
)
from aws_ops_monitor.collectors.network import CommandResult, NetworkCollector
from aws_ops_monitor.collector import Collector
from aws_ops_monitor.config import Config, ConfigError
from aws_ops_monitor.models import HealthState
from aws_ops_monitor.store import MetricStore, _is_current_aws_snapshot
from aws_ops_monitor.web import ReadOnlySQLiteRepository


class FakeLightsailClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get_instance(self, **kwargs):
        self.calls.append(("get_instance", kwargs))
        return {
            "instance": {
                "name": "private-instance-name",
                "publicIpAddress": "203.0.113.41",
                "state": {"name": "running"},
                "isStaticIp": True,
                "networking": {"monthlyTransfer": {"gbPerMonthAllocated": 2}},
            }
        }

    def get_instance_port_states(self, **kwargs):
        self.calls.append(("get_instance_port_states", kwargs))
        return {
            "portStates": [
                {
                    "fromPort": 22,
                    "toPort": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "cidrs": ["0.0.0.0/0"],
                },
                {
                    "fromPort": 80,
                    "toPort": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "cidrs": ["0.0.0.0/0"],
                    "ipv6Cidrs": ["::/0"],
                },
            ]
        }

    def get_instance_metric_data(self, **kwargs):
        self.calls.append(("get_instance_metric_data", kwargs))
        metric_name = kwargs["metricName"]
        if metric_name == "NetworkIn":
            return {
                "metricData": [
                    {"sum": 100},
                    {"sum": 5},
                    {"sum": float("nan")},
                ]
            }
        if metric_name == "NetworkOut":
            return {"metricData": [{"sum": 250}, {"sum": 5}]}
        if metric_name == "CPUUtilization":
            return {"metricData": [{"maximum": 15.0}, {"maximum": 22.5}]}
        if metric_name == "BurstCapacityPercentage":
            return {"metricData": [{"minimum": 88.0}, {"minimum": 91.0}]}
        if metric_name == "StatusCheckFailed":
            return {"metricData": [{"sum": 0}]}
        raise AssertionError(f"unexpected metric: {metric_name}")

    def get_alarms(self, **kwargs):
        self.calls.append(("get_alarms", kwargs))
        return {"alarms": [{"name": "private-alarm-name", "state": "OK"}]}


class LightsailCollectorTests(unittest.TestCase):
    def test_uses_only_fixed_read_calls_and_sums_current_month_metrics(self) -> None:
        client = FakeLightsailClient()
        observed_at = 1_768_438_800.0
        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            transfer_allowance_bytes=2_000,
            transfer_allowance_provenance="operator-configured",
            client=client,
            clock=lambda: observed_at,
            monotonic=lambda: 10.0,
        ).collect()

        self.assertEqual(snapshot.health.state, HealthState.HEALTHY)
        values = {gauge.name: int(gauge.value) for gauge in snapshot.gauges}
        self.assertEqual(values["network_in_month_bytes"], 105)
        self.assertEqual(values["network_out_month_bytes"], 255)
        self.assertEqual(values["transfer_used_month_bytes"], 360)
        self.assertEqual(values["transfer_plan_allocation_bytes"], 2_000)
        self.assertEqual(values["cpu_utilization_max_percent"], 22)
        self.assertEqual(values["burst_capacity_min_percent"], 88)
        self.assertEqual(values["status_check_failed_count"], 0)
        self.assertEqual(
            snapshot.health.details["plan_allocation_provenance"],
            "operator-configured",
        )
        call_names = [name for name, _arguments in client.calls]
        self.assertEqual(
            call_names,
            [
                "get_instance",
                "get_instance_port_states",
                "get_instance_metric_data",
                "get_instance_metric_data",
                "get_instance_metric_data",
                "get_instance_metric_data",
                "get_instance_metric_data",
                "get_alarms",
            ],
        )
        for name, arguments in client.calls:
            if name == "get_instance_metric_data":
                self.assertEqual(arguments["period"], 300)
                if arguments["metricName"] in {"NetworkIn", "NetworkOut"}:
                    self.assertEqual(arguments["unit"], "Bytes")
                    self.assertEqual(arguments["statistics"], ["Sum"])
                    self.assertEqual(arguments["startTime"].day, 1)
                    self.assertEqual(arguments["startTime"].hour, 0)
                elif arguments["metricName"] == "StatusCheckFailed":
                    self.assertEqual(arguments["unit"], "Count")
                    self.assertEqual(arguments["statistics"], ["Sum"])
                else:
                    self.assertEqual(arguments["unit"], "Percent")
                    expected_statistic = (
                        ["Maximum"]
                        if arguments["metricName"] == "CPUUtilization"
                        else ["Minimum"]
                    )
                    self.assertEqual(arguments["statistics"], expected_statistic)
                if arguments["metricName"] not in {"NetworkIn", "NetworkOut"}:
                    self.assertEqual(
                        (arguments["endTime"] - arguments["startTime"]).seconds,
                        15 * 60,
                    )
            else:
                self.assertNotIn("metricName", arguments)
        alarm_arguments = [
            arguments for name, arguments in client.calls if name == "get_alarms"
        ]
        self.assertEqual(alarm_arguments, [{"monitoredResourceName": "test-instance"}])
        serialized = repr(snapshot)
        self.assertNotIn("test-instance", serialized)
        self.assertNotIn("private-instance-name", serialized)
        self.assertNotIn("203.0.113.41", serialized)
        self.assertNotIn("private-alarm-name", serialized)

    def test_derives_nominal_instance_plan_allocation_from_networking(self) -> None:
        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=FakeLightsailClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()

        allowance = next(
            gauge
            for gauge in snapshot.gauges
            if gauge.name == "transfer_plan_allocation_bytes"
        )
        self.assertEqual(int(allowance.value), 2 * 1024**3)
        self.assertEqual(allowance.labels["provenance"], "aws_instance_networking")
        self.assertEqual(
            snapshot.health.details["plan_allocation_provenance"],
            "aws_instance_networking",
        )

    def test_non_integer_plan_allocation_is_rejected_as_malformed(self) -> None:
        class FractionalAllocationClient(FakeLightsailClient):
            def get_instance(self, **kwargs):
                response = super().get_instance(**kwargs)
                response["instance"]["networking"]["monthlyTransfer"][
                    "gbPerMonthAllocated"
                ] = 1.5
                return response

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=FractionalAllocationClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertNotIn(
            "transfer_plan_allocation_bytes",
            {gauge.name for gauge in snapshot.gauges},
        )
        self.assertIn("plan_allocation", snapshot.health.details["missing_data"])

    def test_five_minute_cache_avoids_duplicate_api_reads(self) -> None:
        client = FakeLightsailClient()
        ticks = iter((10.0, 20.0))
        collector = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=client,
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: next(ticks),
        )
        first = collector.collect()
        second = collector.collect()
        self.assertIs(first, second)
        self.assertEqual(len(client.calls), 8)

    def test_cache_refreshes_at_minimum_interval_boundary(self) -> None:
        client = FakeLightsailClient()
        ticks = iter((10.0, 309.0, 310.0))
        collector = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=client,
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: next(ticks),
        )
        first = collector.collect()
        cached = collector.collect()
        refreshed = collector.collect()
        self.assertIs(first, cached)
        self.assertIsNot(first, refreshed)
        self.assertEqual(len(client.calls), 16)

    def test_freshness_window_tracks_configured_collection_interval(self) -> None:
        observed_at = datetime(2026, 3, 15, 12, 0, tzinfo=UTC).timestamp()
        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            minimum_interval_seconds=3600,
            client=FakeLightsailClient(),
            clock=lambda: observed_at,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.details["fresh_for_seconds"], 7200)
        gauges = {
            gauge.name: (gauge.observed_at, float(gauge.value))
            for gauge in snapshot.gauges
        }
        health = {
            "observed_at": snapshot.health.observed_at,
            "state": snapshot.health.state.value,
            "details": dict(snapshot.health.details),
        }
        self.assertTrue(
            _is_current_aws_snapshot(health, gauges, now=observed_at + 7199)
        )
        self.assertFalse(
            _is_current_aws_snapshot(health, gauges, now=observed_at + 7201)
        )
        health["details"]["fresh_for_seconds"] = "not-a-window"
        self.assertFalse(_is_current_aws_snapshot(health, gauges, now=observed_at))

    def test_unavailable_snapshot_carries_same_freshness_contract(self) -> None:
        def unavailable_factory(_region: str, _timeout: float):
            raise RuntimeError("SDK unavailable")

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            minimum_interval_seconds=86400,
            client_factory=unavailable_factory,
            clock=lambda: 10.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.details["fresh_for_seconds"], 172800)

    def test_network_window_starts_at_exact_utc_month_boundary(self) -> None:
        observed_at = datetime(2026, 3, 1, 0, 0, tzinfo=UTC).timestamp()
        client = FakeLightsailClient()
        LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=client,
            clock=lambda: observed_at,
            monotonic=lambda: 10.0,
        ).collect()
        network_calls = [
            arguments
            for name, arguments in client.calls
            if name == "get_instance_metric_data"
            and arguments["metricName"] in {"NetworkIn", "NetworkOut"}
        ]
        self.assertEqual(len(network_calls), 2)
        for arguments in network_calls:
            self.assertEqual(
                arguments["startTime"], datetime(2026, 3, 1, 0, 0, tzinfo=UTC)
            )
            self.assertEqual(arguments["endTime"].timestamp(), observed_at)

    def test_alarm_pagination_is_bounded_and_resource_scoped(self) -> None:
        private_token = "private-next-page-token"

        class PaginatedClient(FakeLightsailClient):
            def get_alarms(self, **kwargs):
                self.calls.append(("get_alarms", kwargs))
                if "pageToken" not in kwargs:
                    return {
                        "alarms": [{"name": "private-first", "state": "OK"}],
                        "nextPageToken": private_token,
                    }
                self.assert_page_token(kwargs)
                return {"alarms": [{"name": "private-second", "state": "ALARM"}]}

            @staticmethod
            def assert_page_token(arguments):
                if arguments.get("pageToken") != private_token:
                    raise AssertionError("wrong page token")

        client = PaginatedClient()
        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=client,
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        alarm_calls = [args for name, args in client.calls if name == "get_alarms"]
        self.assertEqual(len(alarm_calls), 2)
        self.assertTrue(
            all(
                args["monitoredResourceName"] == "test-instance" for args in alarm_calls
            )
        )
        self.assertEqual(snapshot.health.details["alarm_count"], 2)
        self.assertEqual(snapshot.health.details["active_alarm_count"], 1)
        self.assertNotIn(private_token, repr(snapshot))

    def test_operational_threshold_boundaries_are_inclusive(self) -> None:
        class ThresholdClient(FakeLightsailClient):
            def get_instance_metric_data(self, **kwargs):
                metric_name = kwargs["metricName"]
                if metric_name == "CPUUtilization":
                    self.calls.append(("get_instance_metric_data", kwargs))
                    return {"metricData": [{"maximum": 85.0}]}
                if metric_name == "BurstCapacityPercentage":
                    self.calls.append(("get_instance_metric_data", kwargs))
                    return {"metricData": [{"minimum": 20.0}]}
                return super().get_instance_metric_data(**kwargs)

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=ThresholdClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        risks = set(str(snapshot.health.details["risk_flags"]).split(","))
        self.assertIn("high_cpu", risks)
        self.assertIn("low_burst_capacity", risks)
        self.assertEqual(snapshot.health.details["cpu_utilization_max_percent"], 85.0)
        self.assertEqual(snapshot.health.details["burst_capacity_min_percent"], 20.0)

    def test_running_instance_with_control_plane_risks_is_degraded_and_private(
        self,
    ) -> None:
        class RiskClient(FakeLightsailClient):
            def get_instance(self, **kwargs):
                response = super().get_instance(**kwargs)
                response["instance"]["isStaticIp"] = False
                return response

            def get_instance_port_states(self, **kwargs):
                self.calls.append(("get_instance_port_states", kwargs))
                return {
                    "portStates": [
                        {
                            "fromPort": 1087,
                            "toPort": 1087,
                            "protocol": "tcp",
                            "state": "open",
                            "cidrs": ["0.0.0.0/0", "198.51.100.77/32"],
                            "cidrListAliases": ["private-managed-alias"],
                        },
                        {
                            "protocol": "all",
                            "state": "open",
                            "cidrs": ["0.0.0.0/0"],
                        },
                        {
                            "protocol": "icmp",
                            "state": "open",
                            "cidrs": ["0.0.0.0/0"],
                        },
                        {
                            "protocol": "icmpv6",
                            "state": "open",
                            "ipv6Cidrs": ["::/0"],
                        },
                    ]
                }

            def get_instance_metric_data(self, **kwargs):
                metric_name = kwargs["metricName"]
                if metric_name in {"NetworkIn", "NetworkOut"}:
                    return super().get_instance_metric_data(**kwargs)
                self.calls.append(("get_instance_metric_data", kwargs))
                if metric_name == "CPUUtilization":
                    return {"metricData": [{"maximum": 97.5}]}
                if metric_name == "BurstCapacityPercentage":
                    return {"metricData": [{"minimum": 4.0}]}
                if metric_name == "StatusCheckFailed":
                    return {"metricData": [{"sum": 1}]}
                raise AssertionError(metric_name)

            def get_alarms(self, **kwargs):
                self.calls.append(("get_alarms", kwargs))
                return {
                    "alarms": [
                        {"name": "private-active-alarm", "state": "ALARM"},
                        {"name": "private-unknown-alarm", "state": "INSUFFICIENT_DATA"},
                    ]
                }

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=RiskClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()

        self.assertEqual(snapshot.health.state, HealthState.DEGRADED)
        risks = set(str(snapshot.health.details["risk_flags"]).split(","))
        self.assertTrue(
            {
                "active_alarms",
                "high_cpu",
                "indeterminate_alarms",
                "low_burst_capacity",
                "no_static_ip",
                "status_check_failed",
                "unsafe_world_open_firewall",
            }
            <= risks
        )
        self.assertEqual(snapshot.health.details["unsafe_world_open_rule_count"], 4)
        summaries = str(snapshot.health.details["firewall_open_ports"])
        self.assertIn("all@world_ipv4", summaries)
        self.assertIn("icmp@world_ipv4", summaries)
        self.assertIn("icmpv6@world_ipv6", summaries)
        serialized = repr(snapshot)
        for private_value in (
            "test-instance",
            "private-instance-name",
            "203.0.113.41",
            "198.51.100.77/32",
            "0.0.0.0/0",
            "::/0",
            "private-managed-alias",
            "private-active-alarm",
            "private-unknown-alarm",
        ):
            self.assertNotIn(private_value, serialized)

    def test_stopped_instance_is_unavailable_even_when_reads_succeed(self) -> None:
        class StoppedClient(FakeLightsailClient):
            def get_instance(self, **kwargs):
                response = super().get_instance(**kwargs)
                response["instance"]["state"] = {"name": "stopped"}
                return response

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=StoppedClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.UNAVAILABLE)
        self.assertEqual(snapshot.health.details["instance_state"], "stopped")
        self.assertIn("instance_not_running", snapshot.health.details["risk_flags"])

    def test_partial_and_empty_metric_reads_never_fabricate_zero_values(self) -> None:
        class AccessDenied(Exception):
            def __init__(self):
                self.response = {"Error": {"Code": "AccessDeniedException"}}

        class PartialClient(FakeLightsailClient):
            def get_instance_metric_data(self, **kwargs):
                if kwargs["metricName"] == "NetworkOut":
                    self.calls.append(("get_instance_metric_data", kwargs))
                    raise AccessDenied()
                if kwargs["metricName"] == "CPUUtilization":
                    self.calls.append(("get_instance_metric_data", kwargs))
                    return {"metricData": []}
                return super().get_instance_metric_data(**kwargs)

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=PartialClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.DEGRADED)
        gauge_names = {gauge.name for gauge in snapshot.gauges}
        self.assertIn("network_in_month_bytes", gauge_names)
        self.assertNotIn("network_out_month_bytes", gauge_names)
        self.assertNotIn("transfer_used_month_bytes", gauge_names)
        self.assertNotIn("cpu_utilization_max_percent", gauge_names)
        self.assertEqual(snapshot.health.details["failure_categories"], "access_denied")
        self.assertIn("cpu_utilization", snapshot.health.details["missing_data"])

    def test_missing_structured_responses_are_partial_not_zero(self) -> None:
        class MissingDataClient(FakeLightsailClient):
            def get_instance_port_states(self, **kwargs):
                self.calls.append(("get_instance_port_states", kwargs))
                return {}

            def get_alarms(self, **kwargs):
                self.calls.append(("get_alarms", kwargs))
                return {}

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=MissingDataClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()

        self.assertEqual(snapshot.health.state, HealthState.DEGRADED)
        self.assertNotIn("alarm_count", snapshot.health.details)
        self.assertNotIn("unsafe_world_open_rule_count", snapshot.health.details)
        self.assertIn("alarms", snapshot.health.details["missing_data"])
        self.assertIn("firewall_rules", snapshot.health.details["missing_data"])

    def test_restricted_unexpected_port_is_classified_without_raw_source(self) -> None:
        raw_source = "10.22.0.0/16"

        class RestrictedClient(FakeLightsailClient):
            def get_instance_port_states(self, **kwargs):
                self.calls.append(("get_instance_port_states", kwargs))
                return {
                    "portStates": [
                        {
                            "fromPort": 1087,
                            "toPort": 1087,
                            "protocol": "tcp",
                            "state": "open",
                            "cidrs": [raw_source],
                        }
                    ]
                }

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=RestrictedClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()

        self.assertEqual(snapshot.health.state, HealthState.HEALTHY)
        self.assertEqual(snapshot.health.details["unsafe_world_open_rule_count"], 0)
        self.assertEqual(
            snapshot.health.details["firewall_source_scopes"], "private_ipv4"
        )
        self.assertNotIn(raw_source, repr(snapshot))

    def test_configured_public_ports_drive_world_open_firewall_expectations(
        self,
    ) -> None:
        class HttpsClient(FakeLightsailClient):
            def get_instance_port_states(self, **kwargs):
                self.calls.append(("get_instance_port_states", kwargs))
                return {
                    "portStates": [
                        {
                            "fromPort": 443,
                            "toPort": 443,
                            "protocol": "tcp",
                            "state": "open",
                            "cidrs": ["0.0.0.0/0"],
                        }
                    ]
                }

        default_snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=HttpsClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(
            default_snapshot.health.details["unsafe_world_open_rule_count"], 1
        )

        configured_snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            expected_public_tcp_ports=(22, 80, 443),
            client=HttpsClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(
            configured_snapshot.health.details["unsafe_world_open_rule_count"], 0
        )

    def test_malformed_ip_sources_and_managed_aliases_are_safely_classified(
        self,
    ) -> None:
        malformed_v4 = "999.999.999.999/32"
        malformed_v6 = "gggg::1/128"
        private_alias = "private-managed-alias"

        class SourceShapeClient(FakeLightsailClient):
            def get_instance_port_states(self, **kwargs):
                self.calls.append(("get_instance_port_states", kwargs))
                return {
                    "portStates": [
                        {
                            "fromPort": 22,
                            "toPort": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "cidrs": [malformed_v4],
                            "ipv6Cidrs": [malformed_v6],
                            "cidrListAliases": [private_alias],
                        }
                    ]
                }

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=SourceShapeClient(),
            clock=lambda: 1_768_438_800.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.DEGRADED)
        self.assertEqual(snapshot.health.details["invalid_firewall_rule_count"], 2)
        scopes = set(str(snapshot.health.details["firewall_source_scopes"]).split(","))
        self.assertEqual(scopes, {"invalid_source", "managed_alias"})
        for private_value in (malformed_v4, malformed_v6, private_alias):
            self.assertNotIn(private_value, repr(snapshot))

    def test_access_denied_is_safe_and_does_not_leak_exception_text(self) -> None:
        secret = "credential private-token 198.51.100.9"

        class AccessDenied(Exception):
            def __init__(self):
                self.response = {
                    "Error": {"Code": "AccessDeniedException", "Message": secret}
                }
                super().__init__(secret)

        class DeniedClient:
            def __getattr__(self, _name):
                def denied(**_kwargs):
                    raise AccessDenied()

                return denied

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=DeniedClient(),
            clock=lambda: 10.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.UNAVAILABLE)
        self.assertEqual(snapshot.health.details["failure_categories"], "access_denied")
        self.assertNotIn(secret, repr(snapshot))

    def test_unauthenticated_exception_is_credentials_unavailable(self) -> None:
        secret = "private-credential-context"

        class Unauthenticated(Exception):
            def __init__(self):
                self.response = {
                    "Error": {"Code": "UnauthenticatedException", "Message": secret}
                }
                super().__init__(secret)

        class UnauthenticatedClient:
            def __getattr__(self, _name):
                def denied(**_kwargs):
                    raise Unauthenticated()

                return denied

        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            client=UnauthenticatedClient(),
            clock=lambda: 10.0,
            monotonic=lambda: 10.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.UNAVAILABLE)
        self.assertEqual(
            snapshot.health.details["failure_categories"],
            "credentials_unavailable",
        )
        self.assertNotIn(secret, repr(snapshot))

    def test_custom_aws_endpoint_is_rejected_before_sdk_use(self) -> None:
        with patch.dict(os.environ, {"AWS_ENDPOINT_URL_LIGHTSAIL": "http://127.0.0.1"}):
            with self.assertRaisesRegex(RuntimeError, "custom endpoint"):
                _default_client_factory("ap-southeast-1", 1.0)


class LightsailConfigTests(unittest.TestCase):
    def test_aws_is_disabled_by_default_and_requires_explicit_instance(self) -> None:
        self.assertFalse(Config.from_env({}).aws_enabled)
        with self.assertRaisesRegex(ConfigError, "explicit Lightsail instance"):
            Config.from_env({"AWS_OPS_AWS_ENABLED": "true"})

    def test_allowance_requires_and_preserves_operator_source(self) -> None:
        with self.assertRaisesRegex(ConfigError, "provenance"):
            Config.from_env({"AWS_OPS_TRANSFER_ALLOWANCE_BYTES": "2000"})
        config = Config.from_env(
            {
                "AWS_OPS_TRANSFER_ALLOWANCE_BYTES": "2000",
                "AWS_OPS_TRANSFER_ALLOWANCE_SOURCE": "operator-configured",
            }
        )
        self.assertEqual(config.transfer_allowance_bytes, 2_000)
        self.assertEqual(config.transfer_allowance_provenance, "operator-configured")

    def test_instance_region_and_allowance_inputs_are_validated(self) -> None:
        with self.assertRaisesRegex(ConfigError, "instance_name"):
            Config.from_env({"AWS_OPS_LIGHTSAIL_INSTANCE": "bad instance;value"})
        with self.assertRaisesRegex(ConfigError, "positive integer"):
            Config.from_env({"AWS_OPS_TRANSFER_ALLOWANCE_BYTES": "2TB"})


class LightsailProjectionTests(unittest.TestCase):
    def test_orchestrator_aws_failure_uses_configured_freshness_window(self) -> None:
        class BrokenCollector:
            def collect(self):
                raise RuntimeError("private AWS failure")

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            config = Config(
                database_path=database,
                host_enabled=False,
                xray_enabled=False,
                network_enabled=False,
                path_probes_enabled=False,
                aws_enabled=True,
                lightsail_instance_name="test-instance",
                aws_minimum_interval_seconds=3600,
            )
            with MetricStore(database) as store:
                Collector(
                    config,
                    store,
                    aws_collector=BrokenCollector(),  # type: ignore[arg-type]
                    clock=lambda: 10.0,
                    monotonic=lambda: 10.0,
                ).collect_once()
                sample = store.fetch_health_samples("aws")[-1]
        self.assertEqual(sample["state"], "unavailable")
        self.assertEqual(sample["details"]["fresh_for_seconds"], 7200)
        self.assertNotIn("private AWS failure", repr(sample))

    def test_dashboard_projects_aws_layers_with_operator_provenance(self) -> None:
        now = time.time()
        snapshot = LightsailCollector(
            region="ap-southeast-1",
            instance_name="test-instance",
            transfer_allowance_bytes=2_000,
            transfer_allowance_provenance="operator-configured",
            client=FakeLightsailClient(),
            clock=lambda: now,
            monotonic=lambda: 1.0,
        ).collect()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database) as store:
                store.record_batch(gauges=snapshot.gauges, health=(snapshot.health,))
                writer_overview = store.overview()
            overview = ReadOnlySQLiteRepository(database).overview()

        for projection in (writer_overview, overview):
            aws = projection["traffic"]["aws"]
            self.assertEqual(aws["network_in_month_bytes"], 105)
            self.assertEqual(aws["network_out_month_bytes"], 255)
            self.assertEqual(aws["transfer_used_bytes"], 360)
            self.assertEqual(aws["plan_allocation_bytes"], 2_000)
            self.assertEqual(aws["usage_source"], "lightsail_read_only")
            self.assertEqual(aws["plan_allocation_source"], "operator-configured")
            self.assertNotIn("source", aws)
            self.assertNotIn("test-instance", json.dumps(projection))

    def test_collector_persists_network_and_aws_in_one_batch(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            config = Config(
                database_path=database,
                host_enabled=False,
                xray_enabled=False,
                network_enabled=True,
                path_probes_enabled=False,
                aws_enabled=True,
                lightsail_instance_name="test-instance",
            )
            network = NetworkCollector(
                runner=lambda _command, _timeout: CommandResult(
                    0,
                    "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
                    "LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*\n"
                    "LISTEN 0 4096 127.0.0.1:8787 0.0.0.0:*\n"
                    "LISTEN 0 4096 127.0.0.1:10084 0.0.0.0:*\n",
                ),
                clock=lambda: now,
            )
            aws = LightsailCollector(
                region="ap-southeast-1",
                instance_name="test-instance",
                client=FakeLightsailClient(),
                clock=lambda: now,
                monotonic=lambda: 1.0,
            )
            with MetricStore(database) as store:
                result = Collector(
                    config,
                    store,
                    network_collector=network,
                    aws_collector=aws,
                    clock=lambda: now,
                ).collect_once()
                self.assertEqual(result.network_state, HealthState.HEALTHY)
                self.assertEqual(result.aws_state, HealthState.HEALTHY)
                self.assertTrue(store.fetch_health_samples("path_ssh"))
                self.assertTrue(store.fetch_health_samples("aws"))


if __name__ == "__main__":
    unittest.main()
