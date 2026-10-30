# Contributing

Thank you for your interest in Agent Activity. Issues and pull requests are
welcome.

## Reporting issues

- **Security problems:** follow [SECURITY.md](SECURITY.md). Please don't open a
  public issue.
- **Bugs:** open an issue with the version (`collector.version` in the collected
  file), your OS and Python version, and the smallest log excerpt that shows the
  problem. Remove prompts, paths and secrets from anything you paste.
- **Detection gaps:** open an issue for a risky command that wasn't flagged, or a
  harmless one that was. Include the command text with any secrets masked.

## Making a change

1. Edit the files in `source/`. Never edit `agent-activity.py` directly.
2. Rebuild the script and run the tests:

   ```sh
   python3 source/bundle.py
   python3 -m unittest discover -s tests
   ```

3. Commit the rebuilt `agent-activity.py` with your change. The tests check that
   it matches `source/`.

Keep the code compatible with Python 3.9, which is macOS's built-in `python3`,
and use only the standard library. The tool must run on a machine with nothing
installed.

## Guidelines

- **Put privacy first.** Don't add anything to the collected file that
  [docs/privacy.md](docs/privacy.md) doesn't list. Any change to what is
  collected must update that document in the same pull request.
- **Treat log content as hostile.** Every string from a log reaches the report,
  so clean it, cap its length and escape it.
- **Base rules on published sources.** New detection rules should come from a
  published, licence-compatible rule set, with attribution in
  `source/rules/NOTICE`, or be this project's own rules with a test.
- **Include tests with every change.** Add a fixture under `tests/fixtures/` for
  new log shapes. Fixtures must be synthetic, with no real logs, names or hosts.
- **Write comments that explain why,** not what.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
