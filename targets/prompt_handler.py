#!/usr/bin/env python3
"""Simulated prompt handler (test target for TC-07 / TC-09).

This is NOT a served LLM and loads no model. It is a plain Python function that
returns canned responses to prompt-injection payloads, so the attack can be
recorded as a request/response pair without standing up any model inference.

ATTACKER's hard constraint: it never runs a local LLM server, never loads a
model, and never exposes an HTTP API. This file satisfies that: it is importable
and callable in-process.

A trivial substring guard is included only so the canned response looks like a
handler that refused — it is intentionally weak and is itself part of what
ThreatLoop is meant to learn to detect.
"""

CANNED_OK = "Here are today's featured products: apple juice, orange juice, banana."
CANNED_REFUSAL = "Request cannot be completed as specified."

_INJECTION_MARKERS = (
    "ignore", "disregard", "forget", "system:", "developer mode",
    "end of user input", "reveal", "dump", "exfiltrate", "api key",
    "set aside", "secret", "token", "copy the records",
)


def looks_like_injection(prompt: str) -> bool:
    low = prompt.lower()
    return any(marker in low for marker in _INJECTION_MARKERS)


def handle_prompt(prompt: str) -> dict:
    """Return a canned response record for one prompt. No model is invoked."""
    injected = looks_like_injection(prompt)
    return {
        "prompt": prompt,
        "response": CANNED_REFUSAL if injected else CANNED_OK,
        "flagged": injected,
    }


if __name__ == "__main__":
    import sys
    text = " ".join(sys.argv[1:]) or "What products do you have?"
    print(handle_prompt(text))
