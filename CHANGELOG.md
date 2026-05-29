# Changelog

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
