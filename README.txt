We use bcrypt with BCRYPT_ROUNDS (default: 12). Increase as hardware improves.

Password-reset email configuration
FRONTEND_ORIGIN must be an explicit HTTPS browser-frontend origin for real reset emails.
See docs/reset-email-configuration.md; never configure the API origin or commit real environment values.
