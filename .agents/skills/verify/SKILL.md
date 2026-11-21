---
name: verify
description: Use when independently checking whether a requested result actually works, including translating requirements into explicit acceptance criteria.
---
# Verify — Adversarial Completion Check

## Purpose
Prevent premature completion by independently checking whether the requested result actually works.

## Operating Rules
- Treat implementation and verification as separate phases.
- Translate requirements into explicit acceptance criteria.
- Test the actual behavior, not merely the existence of files or commands.
- Check both the happy path and important failure paths.
- Inspect generated configuration for syntax, semantics, and unintended changes.
- Verify integrations end-to-end when possible.
- Check that credentials, secrets, permissions, paths, ports, and environment variables are correct without exposing secret values.
- Prefer deterministic tests and observable evidence.
- If verification cannot be performed, clearly state what was and was not verified.
- Never claim success based solely on an expected outcome.

## Verification Sequence
1. Identify acceptance criteria
2. Validate syntax/configuration
3. Validate component behavior
4. Validate integration behavior
5. Test relevant edge/failure cases
6. Compare actual result against requested result
7. Report evidence and remaining uncertainty

## Completion Rule
Use DONE only when the acceptance criteria have been demonstrated. Otherwise report the exact remaining gap.
