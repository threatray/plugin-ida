# Changelog

## [Unreleased]

- The plugin no longer prints an import error when IDA runs without a GUI (`idat`, idalib); it is skipped there.
- API requests run in the background behind a cancelable wait box and no longer freeze IDA. They time out
  when the host is unreachable, and each request is faster (the fixed 0.7 s delay is gone, connections are reused).
- The settings dialog accepts the instance name or the full address of the web app, rejects anything else, and
  masks the API key. Settings saved by earlier versions with a full address keep working.
- The API key is stored in the keychain of the operating system (macOS Keychain, Windows Credential Manager,
  the Secret Service on Linux) through the new `keyring` dependency. Where no keychain is available it stays
  in the settings file, which only the current user can read.
- The settings file moved from `plugins/threatray/config.json` to `threatray/config.json` in the IDA user
  directory, so upgrading the plugin with a plugin manager no longer deletes it. Existing settings are migrated
  automatically.
- Canceling a request now aborts it instead of leaving it running in the background.
- Attribute Functions applies its results about twice as fast, and re-applying unchanged settings about three
  times as fast. A function name IDA rejects no longer opens a warning dialog per function.
- Retrohunt Functions is available in the pseudocode view and shows progress while it fetches the function list.
- Dialogs of the plugin are attached to the IDA window instead of floating on their own.
- Dark themes installed by the user are recognized by the palette they give IDA, not only the built-in ones
  by name.
- IDA started in batch mode (`-A`) without stored settings no longer stops at the settings dialog.
- Attribute Functions no longer shortens function names that contain `__` (for example `__libc_csu_init`)
  each time the results are applied again. Detection names in function names now use single underscores only.
- Applying Attribute Functions results to 5,000 or more functions shows a wait box and keeps IDA's window
  updating while it runs.
- Hooks, actions and the plugin icon are released when the database is closed.
- The minimum `requests` version is 2.33, the first without known security advisories.
- Fixed errors on unexpected API responses and missing settings being shown as Python tracebacks. Responses are
  checked against the expected field types before they are used.
- Result tables with tens of thousands of rows no longer freeze when rows are shown, filtered or sorted: showing
  76,000 rows took 12 s and now takes a fraction of a second. Long cell text is cut off instead of wrapped.
- Result tables stay responsive with large results: filtering is debounced, and cell colors, fonts and the
  filtered rows are no longer recomputed for every painted cell.
- Result tables: Enter opens the selected entry like a double-click, Ctrl+F focuses the filter, address columns
  sort numerically and use the system fixed-width font, and the input hashes and addresses can be selected.
- Fixed "Show unmatched functions" having no effect on IDA 9.2 and newer.
- Fixed the retrohunt result failing to filter when an input function has no matches, and "Copy link" failing
  on entries without a link.
- Copying several cells neutralizes cells that a spreadsheet would run as a formula; a single cell is copied
  as it is.
- CSV export: cells that a spreadsheet would run as a formula are neutralized, non-ASCII text and commas are
  written unchanged, multi-line cells no longer break rows on Windows, and a failed write shows a message.
- The retrohunt threshold dialog stays open and shows the error when the entered value is invalid.

## [3.0.5] - 2026-11-13

- The plugin can now be installed with `hcli plugin install threatray` on IDA 9.5, and on later IDA releases
  as soon as hcli supports them: `ida-plugin.json` declares `idaVersions` as `>=9.0` instead of a fixed list.
  Manual installation on IDA 8.4 and 8.5 is unchanged.
- The README lists the IDA versions the plugin is tested with (8.4 to 9.4) and how to install it with hcli.

## [3.0.4] - 2026-11-10

- The settings dialog and README ask for the **instance name** instead of the "realm", and explain where to find it.
  Existing settings keep working unchanged.

## [3.0.3] - 2026-10-29

- Fixed a startup crash with Python 3.12 and the Qt bindings bundled with IDA 8.4.
- Fixed navigating to an address that has no function in the IDA database; the plugin now shows a warning instead of failing.
- Added Qt table view integration tests and Python 3.12 to the compatibility test matrix alongside Python 3.10,
  3.13, and 3.14.

## [3.0.2] - 2026-06-25

- Fixed result views crashing on IDA 9.2+ with `AttributeError: module 'PyQt5.QtWidgets' has no attribute 'QShortcut'`. The plugin now imports PySide6 directly on IDA 9.2+ instead of going through the deprecated PyQt5 shim.

## [3.0.1] - 2026-05-29

- Added PyPI cooldown for supply-chain protection (`exclude-newer = "7 days"`).

## [3.0.0] - 2026-04-16

- Dropped support for Python 3.8; the plugin now requires Python 3.10 or newer.
- Dropped support for IDA 7.x; the plugin now requires IDA 8.4 or newer.
- Renamed the Python package from `threatray_ida_plugin` to `threatray_ida`. Users who scripted against the old package name need to update their imports.

## [2.4.3] - 2026-01-21

- Fixed incorrect warning in Function Retrohunt when selecting multiple functions that share the same UID.
- Improved threshold dialog: shows when selected functions collapse to fewer UIDs and disables input when only one UID.

## [2.4.2] - 2025-12-11

- Fixed function matching for rebased binaries by using address offsets instead of absolute addresses (excluding .NET
  binaries).

## [2.4.1] - 2025-08-27

- Improved cluster analysis settings UI: replaced "Include benign code" checkbox with "Exclude benign code" for better
  clarity.
- Fixed row index display in table views to start at 1 instead of 0.

## [2.4.0] - 2025-07-09

- Added filter sliders for minimum similarity and confidence on cluster analysis and retrohunt results.
- Added filter to show/hide unmatched functions on cluster analysis.

## [2.3.0] - 2025-05-12

- Support for benign code detection annotations.
- Introduction of similarity score and confidence values on code detections, retrohunt and cluster analysis.
- Reworked code detection settings window for improved user experience.

## [2.2.0] - 2025-01-30

- Support for API keys and removal of oauth2 authentication.
- Improvements and bug fixes.

## [2.1.0] - 2024-07-24

- Introduced the possibility to include benign code for `Function Clustering` and added the function size in result
  view.
- Include the analysis label in `Function Retrohunt` result view. Double-clicking on the `Analysis Id` column opens the
  analysis in Threatray and double-clicking on the `File Hash` column starts a `hunt-hash` query in Threatray.
- It is possible to start a `Function Clustering` request from the `Function Retrohunt` result view using the context
  menu.
- It is possible to start a `Function Retrohunt` request from the `Code Detections` or `Function Clustering` result view
  using the context menu.
- Double-clicking on the `Reference Malware File` column in the `Code Detections` result view opens the analysis of this
  hash in Threatray.
- It is possible to export the result of a `Function Clustering`, a `Function Detection` or a `Function Retrohunt` to a
  CSV file.
- Fixed an issue with sorting `Function Clustering` results by prevalence score.

## [2.0.0] - 2024-07-01

- We improved the feature `Code Detections`, simplified the selection of code detections and enhanced the result view.
- We added the feature `Function Clustering`.
- We enhanced also the result view of the feature `Function Retrohunt`.
- Various minor improvements and bug fixes.
