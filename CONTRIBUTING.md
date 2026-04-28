# Contributing Guidelines

The most recent version of this file can be found [here](https://github.com/stellaraedotdev/Standards/blob/main/guidelines/contributing.md)
This project pre-dates this document. Expect messy code and a future overhaul

This is a rough guideline, all guides and policies can be found [at our standards repo](https://github/com/stellaraedotdev/Standards/)

## REPOSITORY SPECIFIC REFERENCES
1. [Stellarae standard RUST guidelines](https://github.com/stellaraedotdev/Standards/blob/main/styleguides/rust.md)
2. [Stellarae TypeScript guidelines](https://github.com/stellaraedotdev/Standards/blob/main/styleguides/typescript.md)
3. Other minor filetypes (CSS, etc can be found [here](https://github.com/stellaraedotdev/Standards/tree/main/styleguides)
## Contribution Flow
1. Open or select a tracked issue with clear acceptance criteria.
2. Create a focused branch from the default branch.
3. Implement the smallest change that satisfies the requirement.
4. Add or update tests and documentation in the same change.
5. Run local validation before opening a pull request.
6. Open a pull request with context, rationale, and risk notes.
7. Address review feedback and keep discussion in the pull request.
8. Merge only after required approvals and checks pass.

## Branch and Commit Expectations
- Use descriptive branch names tied to issue IDs when available.
- Keep commits focused and logically grouped.
- Write commit messages that explain intent and impact.
- Avoid mixing unrelated refactors with functional changes.

## Pull Request Requirements
- Include problem statement, proposed solution, and alternatives considered.
- Link related issues, incidents, or design notes.
- Document user-facing changes and migration requirements.
- Highlight security, accessibility, and performance implications.

## Required Validation Before Review
- All formatting and lint checks pass.
- Relevant tests pass locally and in CI.
- New behavior is covered by tests.
- Documentation changes are included when needed.

## Review and Merge Rules
- Require at least one qualified reviewer.
- Require owner review for sensitive or high-risk areas.
- Resolve all conversations before merge.
- Do not merge while required checks are failing.

## Exception Handling
- If a requirement cannot be met, document why in the pull request.
- Add follow-up issues for deferred work with clear owners and deadlines.
- Use temporary exceptions only with explicit approval.

## Rule Severity
- MUST: Mandatory requirement for quality, safety, or correctness.
- SHOULD: Strong recommendation with rare documented exceptions.
- MAY: Optional improvement when context and time allow.

## Pull Request Checklist
- Change scope is focused and understandable.
- Tests and docs were updated for behavior changes.
- Risks and rollout considerations were documented.
- Required reviews and checks are complete.

<sub>&copy; 2026 Stellarae | Documents licensed under MIT License. Treat the documents outlined here as 'the Software' in terms of the license.</sub>
