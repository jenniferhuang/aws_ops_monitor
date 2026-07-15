from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "deploy" / "verify.sh"


class DeploymentVerificationTests(unittest.TestCase):
    def test_new_database_gets_bounded_first_sample_wait(self) -> None:
        script = VERIFY.read_text(encoding="utf-8")
        deadline = "initial_deadline = time.monotonic() + 60"
        wait = "while before <= 0 and time.monotonic() < initial_deadline:"
        failure = 'raise SystemExit("monitor database has no samples")'

        self.assertLess(script.index(deadline), script.index(wait))
        self.assertLess(script.index(wait), script.index(failure))

    def test_services_are_rechecked_after_observation(self) -> None:
        script = VERIFY.read_text(encoding="utf-8")
        xray_check = "[[ $(docker inspect --format '{{.State.Running}}' xray) == true ]]"
        final_checks = """systemctl is-active --quiet aws-ops-monitor-collector.service
systemctl is-active --quiet aws-ops-monitor-web.service"""

        self.assertLess(script.rindex(xray_check), script.rindex(final_checks))


if __name__ == "__main__":
    unittest.main()
