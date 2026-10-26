"""Run every automated test and print one summary line per file. Exit code 1 if any fail."""
import subprocess, sys
TESTS = ["test_classifier", "test_quic", "test_blocking", "test_capture", "test_security", "test_robustness"]
failed = []
for t in TESTS:
    p = subprocess.run([sys.executable, f"{t}.py"], capture_output=True, text=True)
    print(f"{'PASS' if p.returncode == 0 else 'FAIL'}  {t}")
    if p.returncode:
        failed.append(t); print(p.stdout[-800:], p.stderr[-800:])
print(f"\n{len(TESTS) - len(failed)}/{len(TESTS)} test files passed")
sys.exit(1 if failed else 0)
