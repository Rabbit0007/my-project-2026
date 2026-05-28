# raw-query-control

Minimal Spring-style Java fixture for a security impact path where a request-controlled `orderBy` value reaches a MyBatis raw SQL fragment.

The fixture is intentionally tiny so Graph Search failures can be isolated to bootstrap, reason, explore, evidence, or promotion gate phases.

Additional coverage surface:

- `AdminExportController.export` represents an `/admin/export` style surface.
  Coverage-oriented tests use it to prove discovery continues after the
  `/user/search` raw-query surface has produced a verified capability.
