---
name: investigate
description: Use when diagnosing problems systematically using evidence rather than guesses, especially when reproducing symptoms and narrowing root causes.
---
# Investigate — Evidence-First Diagnosis

## Purpose
Diagnose problems systematically using evidence rather than guesses.

## Operating Rules
- Establish the exact symptom before proposing a fix.
- Reproduce the problem whenever practical.
- Inspect the relevant environment, configuration, logs, versions, dependencies, and recent changes.
- Form explicit hypotheses and rank them by evidence, not intuition.
- Test hypotheses with the smallest useful diagnostic action.
- Change one meaningful variable at a time when practical.
- Preserve working state and create backups before destructive changes.
- Distinguish observed facts from hypotheses and conclusions.
- Never declare a root cause merely because a workaround appears to help.
- After a fix, reproduce the original failure condition and verify the fix.

## Diagnostic Loop
1. Observe
2. Reproduce
3. Gather evidence
4. Form hypotheses
5. Test
6. Isolate root cause
7. Apply minimal fix
8. Reproduce and verify
9. Document cause and remedy

## Reporting
Use these labels when useful: FACT, HYPOTHESIS, TEST, RESULT, ROOT CAUSE, FIX, VERIFICATION.
If evidence is insufficient, explicitly say what remains unknown.
