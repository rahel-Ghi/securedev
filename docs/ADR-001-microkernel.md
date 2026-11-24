# ADR-001: Use a microkernel architecture

## Status
Accepted

## Context
Security scanners each have their own output format and severity scale.
The platform must support adding new scanners without changing core code (FR10).

## Decision
A small core (orchestrator, registry, finding model, quality gate) plus
scanners and reporters as plug-ins. The core only knows interfaces.

## Alternatives considered
- Monolith: simple, but every new scanner means editing core code.
- Shell scripts per tool: quick, but no common format, hard to test.

## Consequences
+ New scanner = one new file and one config line.
+ Core can be tested with mock plug-ins.
- More upfront design work than a simple script.