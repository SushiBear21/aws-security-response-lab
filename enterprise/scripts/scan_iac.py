"""Zero-dependency guardrail scan of newly added local Terraform and AWS blueprint."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def scan():
    violations = []
    root = ROOT / "terraform"
    for file in root.glob("*.tf"):
        code = file.read_text()
        if re.search(r'\b(?:provider\s+"aws"|resource\s+"aws_|backend\s+"s3"|(?:local|remote)-exec)\b', code):
            violations.append(f"{file.name}: cloud provider, remote backend, or provisioner in no-cloud module")
        for match in re.findall(r'resource\s+"([^"]+)"', code):
            if match != "terraform_data":
                violations.append(f"{file.name}: non-local Terraform resource {match}")
    forbidden = ("BEGIN PRIVATE KEY", "AKIA", "ASIA")
    for file in ROOT.rglob("*"):
        if not file.is_file() or file.suffix not in {".tf", ".py", ".rego", ".json", ".md", ".yml"}:
            continue
        content = file.read_text()
        if any(word in content for word in forbidden):
            violations.append(f"{file.relative_to(ROOT)}: possible credential literal")
    return violations


if __name__ == "__main__":
    failures = scan()
    if failures:
        raise SystemExit("\n".join(failures))
    print("PASS: no-cloud Terraform module and checked-in content guardrails")
