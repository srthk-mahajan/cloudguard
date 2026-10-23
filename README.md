# CloudGuard AWS Scanner (with CPSA credential hygiene)

A Python tool that **audits the password and credential security of a cloud account** and produces a
risk report mapped to **NIST SP 800-63B** (primary), **CIS AWS Foundations** and **OWASP ASVS**.

The cloud is simulated with [`moto`](https://github.com/getmoto/moto) (an in-memory fake of AWS), so it
needs **no AWS account, no Docker, no LocalStack and no internet login**. The audit code is plain `boto3`.

## What it checks

| Area | Examples | Module |
|---|---|---|
| IAM password policy | min length < 8 / < 14, no reuse prevention, forced expiry | `iam_auditor.py` |
| IAM users and keys | console user without MFA, access key older than 90 days, credential unused 45+ days, root account issues | `iam_auditor.py` |
| Hardcoded secrets | AWS keys, passwords, private keys, DB connection strings, high-entropy tokens | `secrets_scanner.py` |
| Password strength | length, entropy, common-password list, patterns, leetspeak, zxcvbn | `strength_engine.py` |
| Secure storage | peppered (Secrets Manager) + salted bcrypt/Argon2, hash-only record in DynamoDB | `secure_store.py` |
| Governance | role checks (+ equivalent IAM policy), JSON audit log that never holds secrets | `access_control.py`, `audit_logger.py` |
| Output | severity-ranked findings, NIST/CIS/ASVS mapping, risk score, CSV | `compliance_mapper.py`, `report.py` |

## Quick start

```bash
pip install -r requirements.txt        # zxcvbn is optional
python -m pytest -q                    # 50 tests
python -m cpsa.cli demo                # full end-to-end run
python -m cpsa.cli audit --harden      # IAM audit, fix the account, audit again
python -m cpsa.cli strength            # hidden prompt for a password
python -m cpsa.cli scan cpsa/data/sample_app.txt
python -m cpsa.cli audit --role viewer # access control: denied
streamlit run app.py                     # optional browser UI
python -m cloudguard.cli scan             # CloudGuard insecure fixture scan
python -m cloudguard.cli scan --secure    # secure comparison fixture
python -m cloudguard.cli evaluate         # labelled rule evaluation
```

**Google Colab:** upload `cloud_password_analyzer.zip` and `CPSA_Demo.ipynb`, open the notebook, `Runtime > Run all`.
See `GUIDE.md` for the full walkthrough and demo script.

CloudGuard adds read-only S3, EC2, IAM and RDS configuration checks without
moving or renaming any CPSA module. Open [CloudGuard_Demo.ipynb](CloudGuard_Demo.ipynb)
for the Run All demonstration.
The catalogue records `cpsa.iam_auditor.audit_iam` as the authoritative source
for the existing IAM password and credential rules.

## CloudGuard scoring and scope

- **Coverage** = `100 * evaluated / total`; `UNKNOWN` results from denied,
  throttled, timed-out, or unsupported collection are shown separately and
  never counted as passes.
- **Posture** = `100 * passed / (passed + failed)`.
- **Risk** = severity weight × internet exposure factor × blast-radius factor,
  summed and capped at 100. Findings are sorted by this priority formula.
- The catalogue cites CIS AWS Foundations benchmark versions where applicable,
  but coverage is partial and CloudGuard is not a certification or legal
  compliance result. GDPR/DPDP text is informational only.

CloudGuard uses moto fixtures only. It does not read S3 objects or database
records. Moto cannot enable encryption on an existing RDS instance, so verified
remediation reports that rule as `UNSUPPORTED` and recommends replacement and
migration.

## Use as a library

```python
from cpsa.cloud_sim import CloudSimulation
from cpsa.pipeline import run_full_audit

with CloudSimulation() as sim:                  # one mock AWS account for the whole run
    result = run_full_audit(sim)                # seeds an insecure fake company, audits everything
    print(result["report"]["risk_score"])
    print(result["report"]["table"].head())     # pandas DataFrame, ready for any UI
```

Every module returns plain data (`Finding` objects, dicts, DataFrames), so a UI (Streamlit/Gradio) can sit on top without changing the core.

## Streamlit demo

Install the requirements and run `streamlit run app.py`. The app keeps one moto
mock account in the Streamlit session, offers buttons to seed the deliberately
insecure account and run the full audit, displays the severity-ranked report,
provides a CSV download, and includes a password strength checker. Selecting
the `viewer` role demonstrates the denied audit request.

## Security rules the code follows
- No raw password or secret in logs, reports, the trace or DynamoDB (enforced by `tests/test_no_leak.py`).
- Pepper comes from Secrets Manager, not source code.
- Strength results never contain the password or any slice of it; secret findings are masked.
"# cloudguard" 
