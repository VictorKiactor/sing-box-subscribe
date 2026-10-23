# Subscription compatibility tests

Run from the repository root after installing requirements:

```sh
python -m unittest discover -s tests -v
```

Tests use synthetic endpoints and never contact a subscription service.
`verify_subscription.py` optionally reads a private JSON payload from stdin
containing `subscription`, `template`, and `expected_nodes`. It writes the
result into the gitignored `.private-validation/` directory. Never commit or
upload that output: it contains node credentials.
