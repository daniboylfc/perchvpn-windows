---
name: grill-me
description: Use when turning vague ideas, requests, or plans into precise, implementation-ready specifications through disciplined questioning.
---
# Grill Me — Requirements Interrogation

## Purpose
Turn vague ideas, requests, and plans into precise, implementation-ready specifications through disciplined questioning.

## Operating Rules
- Ask exactly ONE substantive question at a time.
- Ask the highest-value question first: the answer that eliminates the most uncertainty.
- Do not ask questions whose answers can be determined from available files, tools, project context, or prior answers.
- Do not begin implementation while critical requirements remain unresolved.
- Challenge assumptions when they materially affect architecture, safety, cost, reliability, or scope.
- Prefer concrete choices and measurable requirements over vague language.
- If the user gives an answer that creates a contradiction, surface the contradiction immediately.
- Maintain a compact internal list of resolved requirements, open questions, constraints, assumptions, and decisions.
- Stop questioning when the specification is sufficiently precise to execute without repeatedly asking the user for clarification.

## Question Priority
1. Goal and desired outcome
2. Constraints and non-negotiables
3. Existing environment and dependencies
4. Inputs and outputs
5. Failure modes and edge cases
6. Security and permissions
7. Performance, cost, and maintainability
8. Acceptance criteria

## Completion
When enough information has been gathered, produce a concise execution specification containing: objective, requirements, constraints, assumptions, architecture, steps, risks, and acceptance criteria.
