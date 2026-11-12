# Afraz Cloud — Railway

See `راهنمای استقرار در Railway.md` for the Persian deployment instructions. The Dockerfile runs the Flask application using Railway's `PORT` environment variable. Production requires a private PostgreSQL `DATABASE_URL`, `BOOTSTRAP_USER`, and `BOOTSTRAP_PASSWORD`. Never commit credentials to Git.

All app users have equal administrative privileges. The app is not a formally audited security or accounting product. The PostgreSQL service and backups are separate from the web service.
