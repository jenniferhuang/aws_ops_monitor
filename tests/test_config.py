from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from aws_ops_monitor.config import Config, ConfigError


class ConfigTests(unittest.TestCase):
    def test_defaults_to_thirty_seconds_and_xray_disabled(self) -> None:
        config = Config.from_env({"XDG_STATE_HOME": "/tmp/test-state"})
        self.assertEqual(config.interval_seconds, 30.0)
        self.assertEqual(
            config.database_path,
            Path("/tmp/test-state/aws-ops-monitor/metrics.sqlite3"),
        )
        self.assertTrue(config.host_enabled)
        self.assertFalse(config.xray_enabled)
        self.assertIsNone(config.xray_user_hash_key)
        self.assertEqual(config.raw_retention_days, 7)
        self.assertEqual(config.rollup_retention_days, 400)
        self.assertEqual(config.retention_prune_interval_seconds, 3600.0)

    def test_enabling_xray_requires_hash_key(self) -> None:
        with self.assertRaisesRegex(ConfigError, "requires a private user hashing key"):
            Config.from_env({"AWS_OPS_XRAY_ENABLED": "true"})

    def test_hash_key_is_not_in_repr(self) -> None:
        secret = "this-is-a-private-hash-key"
        config = Config.from_env(
            {
                "AWS_OPS_XRAY_ENABLED": "true",
                "AWS_OPS_XRAY_USER_HASH_KEY": secret,
            }
        )
        self.assertNotIn(secret, repr(config))
        self.assertEqual(config.xray_user_hash_key, secret.encode())

    def test_hash_key_file_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hash.key"
            path.write_text("a-private-file-key")
            path.chmod(0o600)
            config = Config.from_env(
                {
                    "AWS_OPS_XRAY_ENABLED": "yes",
                    "AWS_OPS_XRAY_USER_HASH_KEY_FILE": str(path),
                }
            )
        self.assertEqual(config.xray_user_hash_key, b"a-private-file-key")

    def test_hash_key_file_rejects_group_or_world_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hash.key"
            path.write_text("a-private-file-key")
            path.chmod(0o644)
            with self.assertRaisesRegex(ConfigError, "owner-readable only"):
                Config.from_env(
                    {
                        "AWS_OPS_XRAY_ENABLED": "true",
                        "AWS_OPS_XRAY_USER_HASH_KEY_FILE": str(path),
                    }
                )

    def test_xray_api_must_remain_loopback(self) -> None:
        with self.assertRaisesRegex(ConfigError, "loopback"):
            Config.from_env({"AWS_OPS_XRAY_API_SERVER": "10.0.0.5:10084"})

    def test_unsafe_container_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unsafe"):
            Config.from_env({"AWS_OPS_XRAY_CONTAINER": "xray; touch /tmp/pwned"})

    def test_interval_is_bounded(self) -> None:
        with self.assertRaisesRegex(ConfigError, "between 5 and 3600"):
            Config.from_env({"AWS_OPS_INTERVAL_SECONDS": "1"})

    def test_database_mode_supports_private_read_only_group(self) -> None:
        self.assertEqual(Config.from_env({}).database_file_mode, 0o600)
        self.assertEqual(
            Config.from_env({"AWS_OPS_DB_FILE_MODE": "0640"}).database_file_mode,
            0o640,
        )
        with self.assertRaisesRegex(ConfigError, "0600 or 0640"):
            Config.from_env({"AWS_OPS_DB_FILE_MODE": "0666"})

    def test_retention_is_bounded_and_configurable(self) -> None:
        config = Config.from_env(
            {
                "AWS_OPS_RAW_RETENTION_DAYS": "14",
                "AWS_OPS_ROLLUP_RETENTION_DAYS": "500",
                "AWS_OPS_RETENTION_INTERVAL_SECONDS": "7200",
            }
        )
        self.assertEqual(config.raw_retention_days, 14)
        self.assertEqual(config.rollup_retention_days, 500)
        self.assertEqual(config.retention_prune_interval_seconds, 7200.0)
        for value in ("0", "31", "not-a-number"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                Config.from_env({"AWS_OPS_RAW_RETENTION_DAYS": value})
        for value in ("29", "801", "not-a-number"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                Config.from_env({"AWS_OPS_ROLLUP_RETENTION_DAYS": value})
        with self.assertRaisesRegex(ConfigError, "between 300 and 86400"):
            Config.from_env({"AWS_OPS_RETENTION_INTERVAL_SECONDS": "60"})

    def test_probe_defaults_and_destination_validation(self) -> None:
        config = Config.from_env({})
        self.assertTrue(config.path_probes_enabled)
        self.assertEqual(config.probe_public_hostname, "v2.hermes-node.com")
        self.assertEqual(config.probe_public_path, "/302")
        self.assertEqual(config.warp_proxy_server, "127.0.0.1:1087")
        self.assertGreaterEqual(config.probe_minimum_interval_seconds, 300)
        with self.assertRaisesRegex(ConfigError, "valid DNS hostname"):
            Config.from_env({"AWS_OPS_PROBE_PUBLIC_HOST": "127.0.0.1"})
        with self.assertRaisesRegex(ConfigError, "bounded absolute path"):
            Config.from_env({"AWS_OPS_PROBE_PUBLIC_PATH": "/302\r\nHost: private"})
        with self.assertRaisesRegex(ConfigError, "loopback"):
            Config.from_env({"AWS_OPS_WARP_PROXY_SERVER": "0.0.0.0:1087"})
        with self.assertRaisesRegex(ConfigError, "between 300 and 86400"):
            Config.from_env({"AWS_OPS_PROBE_INTERVAL_SECONDS": "299"})

    def test_udp_listener_policy_is_explicit(self) -> None:
        config = Config.from_env(
            {
                "AWS_OPS_EXPECTED_PUBLIC_UDP_PORTS": "443,53",
                "AWS_OPS_EXPECTED_LOOPBACK_UDP_PORTS": "5353",
            }
        )
        self.assertEqual(config.expected_public_udp_ports, (53, 443))
        self.assertEqual(config.expected_loopback_udp_ports, (5353,))


if __name__ == "__main__":
    unittest.main()
