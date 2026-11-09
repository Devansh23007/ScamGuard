"""Usage:  python cli.py "message text"   |   echo "text" | python cli.py   |   --no-llm / --json"""
import argparse
import json
import sys

import agent


def main():
    p = argparse.ArgumentParser(description="ScamGuard scam detector")
    p.add_argument("text", nargs="?", help="message to analyze (or pipe via stdin)")
    p.add_argument("--no-llm", action="store_true", help="rules only, no API calls")
    p.add_argument("--json", action="store_true", help="output JSON")
    a = p.parse_args()
    text = a.text or sys.stdin.read()
    r = agent.analyze(text, use_llm=not a.no_llm)
    if a.json:
        print(json.dumps(r.to_dict(), indent=2, ensure_ascii=False))
        return
    print(f"\n{r.verdict_label}  |  risk {r.score}/100  |  {r.scam_type}\n{r.summary}\n")
    for s in r.signals:
        print(f"  • {s.title}: {s.detail}")
    print("\nWhat to do:")
    for x in r.actions:
        print(f"  - {x}")
    if r.llm_error:
        print(f"\n(AI analysis unavailable: {r.llm_error})")


if __name__ == "__main__":
    main()
