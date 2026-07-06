# Contributing to LoginGuard

Thank you for considering a contribution to the Login Attempt Control System!

## Getting Started

1. Fork the repository and clone your fork locally.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
3. Run the test suite before making changes to confirm a clean baseline:
   ```bash
   pytest -v
   ```

## Development Guidelines

- Follow **PEP 8** style conventions.
- Add **type hints** and **docstrings** to all new functions and classes.
- Keep security-sensitive logic (authentication, hashing, session handling)
  isolated in the appropriate modules (`auth.py`, `security.py`, `session_manager.py`).
- Never log plaintext passwords or sensitive credentials.
- All new database access must use parameterized queries — never string-formatted SQL.
- Add or update `pytest` tests for any behavioral change.

## Submitting Changes

1. Create a feature branch: `git checkout -b feature/my-feature`.
2. Commit your changes with clear, descriptive messages.
3. Ensure `pytest` passes locally.
4. Open a pull request describing the change and its motivation.

## Reporting Security Issues

If you discover a security vulnerability, please avoid opening a public issue.
Instead, describe the issue privately to the maintainers so it can be addressed
responsibly before public disclosure.

## Code of Conduct

Be respectful, constructive, and collaborative. This project is intended as an
educational resource — contributions that improve clarity, security, or test
coverage are especially welcome.
