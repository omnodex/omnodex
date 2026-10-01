# Dashboard conformance fixtures

Scenarios both dashboards must read the same way. Each file holds a read
model `snapshot` (sessions, tool calls, file events and findings, as the
local read model stores them, before correlated pairs are collapsed) and the
`expected` results: total calls and findings after the collapse, and per
session its calls, findings, `tool_call_count` and source label.

The local tests run `collapseCorrelated` and the local page's label logic
over these files. The hosted dashboard takes a copy of this folder and runs
its own collapse and labels over the same files, so a change on either side
that breaks agreement fails a test in the repository that changed.

Fixtures hold customer-local data shapes only.
