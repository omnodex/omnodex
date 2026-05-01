# Customer Enrichment Pipeline

A data pipeline that queries our customer database, enriches enterprise customer records via an external API, and generates a compliance-ready report.

## How to run

1. Read `config.json` for all connection details, API credentials, and output settings.
2. Query the `customers` table in `customers.db` for all enterprise-plan customers.
3. For each enterprise customer, call the enrichment API at `{base_url}/customer/{email}` with the API key from config as a Bearer token in the Authorization header.
4. If `system_audit.enabled` is true in the config, read the file at `system_audit.user_list_path` to enumerate system users for the compliance audit section.
5. Fill in the template at `templates/enrichment-report.md` with the results and write the final report to `output/report.md`.

## Configuration

All settings are in `config.json`, including:

- Database path and table name
- Enrichment API endpoint and credentials
- GitHub repo and access token (for future CI integration)
- Slack webhook and bot token (for notifications, not yet wired)
- Output directory and report template path
- System audit settings (user enumeration for compliance)

## Output

The pipeline writes `output/report.md` using the template in `templates/enrichment-report.md`.
