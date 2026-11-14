"""Composed example queries that combine several of the worker's own objects.

Each SQL is defined once here and referenced from every place it is published:
the ``main`` schema's ``vgi.example_queries`` (:mod:`vgi_pii.worker`), the
example list of the object that drives the query (:mod:`vgi_pii.scalars` /
:mod:`vgi_pii.tables`), and -- for the offline, deterministic ones --
``detect_pii``'s ``vgi.executable_examples``. ``test/sql/compose.test`` runs
them end to end.

``detect_pii`` only accepts literal arguments (DuckDB rejects a LATERAL column
parameter for it), so the per-row compositions over a table column use the
scalars, and ``detect_pii`` composes over a single literal document.
"""

from __future__ import annotations

# A small inline "support tickets" table shared by the per-row compositions.
_TICKETS_CTE = (
    "WITH tickets(id, body) AS (VALUES "
    "(1, 'Hi, this is John Smith, my email is john.smith@example.com'), "
    "(2, 'Please charge my card 4111-1111-1111-1111 today'), "
    "(3, 'The printer on floor 3 is jammed again'), "
    "(4, 'Jane Doe can be reached at jane@example.org'))"
)

# has_pii (filter) + redact (scrub) + pii_types (summary), driven by redact.
SCRUB_TICKETS = {
    "description": (
        "Scrub a ticket column: keep only tickets where has_pii fires, and show each one's "
        "tag-redacted text next to the sorted list of PII types found in it (the clean "
        "printer ticket is filtered out)."
    ),
    "sql": (
        f"{_TICKETS_CTE} "
        "SELECT id, pii.main.redact(body) AS redacted, pii.main.pii_types(body) AS pii_found "
        "FROM tickets WHERE pii.main.has_pii(body) ORDER BY id"
    ),
}

# pii_types (per row, unnested) LEFT-joined from the entity_types vocabulary table,
# driven by pii_types.
TYPE_PREVALENCE = {
    "description": (
        "PII prevalence report: for every entity type the analyzer recognises (the "
        "entity_types table), count how many tickets contain it according to pii_types, "
        "most common first; recognizable types never seen report 0."
    ),
    "sql": (
        f"{_TICKETS_CTE}, "
        "found AS (SELECT id, unnest(pii.main.pii_types(body)) AS entity_type FROM tickets) "
        "SELECT e.entity_type, count(DISTINCT f.id) AS tickets "
        "FROM pii.main.entity_types AS e LEFT JOIN found AS f USING (entity_type) "
        "GROUP BY e.entity_type ORDER BY tickets DESC, e.entity_type"
    ),
}

# pii_types at the default 0.5 threshold EXCEPT detect_pii at 0.9, driven by
# detect_pii's score_threshold.
THRESHOLD_DROPOUTS = {
    "description": (
        "Tune the confidence threshold: list the entity types pii_types finds at the default "
        "0.5 threshold that detect_pii no longer reports at score_threshold := 0.9 (here the "
        "0.85-confidence PERSON and the 0.5-confidence URL; the 1.0 EMAIL_ADDRESS survives)."
    ),
    "sql": (
        "SELECT unnest(pii.main.pii_types("
        "'Hi, this is John Smith, my email is john.smith@example.com')) AS entity_type "
        "EXCEPT SELECT entity_type FROM pii.main.detect_pii("
        "'Hi, this is John Smith, my email is john.smith@example.com', score_threshold := 0.9) "
        "ORDER BY entity_type"
    ),
}

COMPOSED_EXAMPLES = [SCRUB_TICKETS, TYPE_PREVALENCE, THRESHOLD_DROPOUTS]
