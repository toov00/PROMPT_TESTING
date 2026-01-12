# Test Reports

This directory contains generated security reports from testing runs.

## Report Structure

Reports are JSON files with the following structure:

```json
{
  "summary": {
    "total_tests": 19,
    "vulnerabilities_found": 7,
    "vulnerability_rate": "36.8%",
    "test_date": "2025-01-12T10:30:00"
  },
  "vulnerabilities_by_severity": {
    "critical": 3,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "vulnerabilities_by_category": {
    "direct_override": 2,
    "role_playing": 3,
    "delimiter_confusion": 1,
    "obfuscation": 1
  },
  "all_results": [
    {
      "attack_name": "Direct Instruction Override",
      "category": "direct_override",
      "payload": "Ignore all previous instructions...",
      "response": "LLM response here",
      "is_successful": true,
      "severity": "critical",
      "detection_reason": "Leaked forbidden keyword: 'password123'",
      "timestamp": "2025-01-12T10:30:15"
    }
  ]
}
```

## Viewing Reports

Reports can be viewed with any JSON viewer or programmatically:

```python
import json

with open('reports/my_report.json', 'r') as f:
    report = json.load(f)

print(f"Total tests: {report['summary']['total_tests']}")
print(f"Vulnerabilities: {report['summary']['vulnerabilities_found']}")
```

## Report Files

- Reports are automatically saved here when running tests
- Filename format: `{description}_report.json`
- `.gitignore` prevents reports from being committed (they may contain sensitive test data)

## Analyzing Results

Critical findings to address immediately:
- **Critical severity**: Data leakage (passwords, API keys, PII)
- **High severity**: Successful instruction bypass
- **Medium severity**: Partial compliance with injection attempts

Focus on fixing critical and high severity issues first.
