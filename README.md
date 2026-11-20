# QC Analytical Results Monitoring — Cloud trial

PostgreSQL adaptation of V4. Intended for dummy data only pending security, integration and validation tests. No existing SQLite records migrated.

1. Create a new private GitHub repository. Extract and upload the files in this folder (not the ZIP). Do not add passwords or database connection strings to the repository.
2. In Render My Workspace, create a Web Service from that repository. Select Python, Free, Singapore, build `pip install -r requirements.txt`, start `python server.py`. Health check `/health`.
3. In Neon, select project `qc-analytical-monitoring-trial`, database `qc_monitoring`. Use Connect to copy its PostgreSQL connection string (TLS enabled). Put it only in Render's secret environment variable `DATABASE_URL`.
4. Set `QC_ADMIN_PASSWORD` and `QC_ADMIN2_PASSWORD` to different strong passwords (12+ characters), known only to their authorized administrators. Set `QC_HTTPS=1`. Never share credentials in chat.
5. Deploy. Check logs and the actual URL provided by Render. Both Weni admin email addresses are bootstrapped when the application starts successfully. Existing account passwords are not reset by restart; use User Management for subsequent resets.
6. Test login, permissions, persistence after restart, inspection entry, correction, audit and reporting using dummy records before real use.

This is a pilot, not validated production software. V4 features and limitations remain; full product/specification master, automatic evaluation, normalized inspection detail, drafts/review, backup/recovery validation, security hardening and other original requirements remain incomplete. Audit trigger blocks normal row mutation but DB owners can alter schema. SQLite data must be separately migrated if needed. Free plan limits apply.
