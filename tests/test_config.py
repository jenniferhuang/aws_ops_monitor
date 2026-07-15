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


if __name__ == "__main__":
    unittest.main()
