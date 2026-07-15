from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "aws_ops_monitor" / "static" / "app.js"


class StaticDashboardJavaScriptTests(unittest.TestCase):
    def test_missing_values_and_progress_labels_are_not_coerced_to_zero(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable")
        script = r"""
const fs = require("fs");
const vm = require("vm");
const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) elements.set(id, { id, textContent: "", value: 0 });
  return elements.get(id);
};
const document = {
  addEventListener() {},
  getElementById: element,
};
const window = {
  addEventListener() {},
  clearTimeout() {},
  setInterval() { return 1; },
  setTimeout() { return 1; },
};
const context = vm.createContext({
  AbortController,
  console,
  document,
  fetch: async () => { throw new Error("not used"); },
  window,
});
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), context);
for (const missing of [null, undefined, false, true, "", "   ", {}, []]) {
  if (context.finiteNumber(missing) !== null) {
    throw new Error(`missing value was coerced: ${String(missing)}`);
  }
}
if (context.finiteNumber("12.5") !== 12.5) throw new Error("numeric string rejected");
context.setProgress("cpu", null, null, 75);
if (element("cpu-bar").value !== 75 || element("cpu-label").textContent !== "75%") {
  throw new Error("direct percentage label is incorrect");
}
context.setProgress("memory", 500, 1000, null);
if (element("memory-bar").value !== 50 || element("memory-label").textContent !== "500 B / 1000 B") {
  throw new Error("used/total progress is incorrect");
}
"""
        result = subprocess.run(
            [node, "-e", script, str(APP)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
