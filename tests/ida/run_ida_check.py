"""Runs the IDA integration checks: starts a real IDA on a scratch profile and evaluates the result file.

    python tests/ida/run_ida_check.py --ida-dir <IDA> --input <binary> --mode headless
    python tests/ida/run_ida_check.py --ida-dir <IDA> --input <binary> --mode gui [--without-settings]

The GUI mode needs a display (xvfb-run on Linux). IDA_LICENSE, if set, is passed on as -Olicense:.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

REPOSITORY = Path(__file__).resolve().parents[2]
PLUGIN_FILES = ('threatray_plugin.py', 'ida-plugin.json', 'threatray_ida')
EXPECTED_UNLOAD = ['unregister_action'] * 4 + ['free_custom_icon']
TRACEBACK_MARKER = 'Traceback (most recent call last)'
BINARIES = {'headless': ('idat', 'idat64', 'idat.exe'), 'gui': ('ida', 'ida64', 'ida.exe')}


def find_binary(ida_dir: Path, mode: str) -> Path:
    for name in BINARIES[mode]:
        # the installation directory itself, or an application bundle in or below it on macOS
        for candidate in [ida_dir / name, *sorted(ida_dir.glob(f'**/Contents/MacOS/{name}'))]:
            if candidate.is_file():
                return candidate
    raise SystemExit(f'no {mode} IDA binary found in {ida_dir}')


def prepare_profile(profile: Path, seed: Path, mode: str, with_settings: bool) -> None:
    profile.mkdir(parents=True, exist_ok=True)
    # the accepted EULA (ida.reg) and a key file, if the licence is kept in the user directory
    for item in list(seed.glob('ida.reg')) + list(seed.glob('*.hexlic')):
        if not (profile / item.name).exists():
            shutil.copy2(item, profile / item.name)
    (profile / 'cfg').mkdir(exist_ok=True)
    # IDA 9.2+ asks about its PyQt5 shim in a dialog that ignores batch mode
    (profile / 'cfg' / 'idapython.cfg').write_text(
        '#if __IDAVER__ >= 920\nIDAPYTHON_USE_PYQT5_SHIM = 0\n#endif\n', encoding='utf-8')
    if mode != 'gui':
        return
    plugin_directory = profile / 'plugins' / 'threatray'
    shutil.rmtree(plugin_directory, ignore_errors=True)
    plugin_directory.mkdir(parents=True)
    for name in PLUGIN_FILES:
        source = REPOSITORY / name
        if source.is_dir():
            shutil.copytree(source, plugin_directory / name, ignore=shutil.ignore_patterns('__pycache__'))
        else:
            shutil.copy2(source, plugin_directory / name)
    settings_file = profile / 'threatray' / 'config.json'
    shutil.rmtree(settings_file.parent, ignore_errors=True)
    if with_settings:
        settings_file.parent.mkdir(parents=True)
        settings_file.write_text(json.dumps({'realm': 'integration-check', 'api_key': 'not-a-real-key'}),
                                 encoding='utf-8')


def print_stall_report(stacks_file: Path) -> None:
    if stacks_file.is_file() and stacks_file.stat().st_size:
        print('[ida-check] where IDA was when the checks stalled:')
        print(stacks_file.read_text(encoding='utf-8', errors='replace')[-5000:])


def evaluate(result: Dict, mode: str, with_settings: bool) -> List[str]:
    problems = list(result.get('failures', []))
    if not result.get('passed'):
        problems.append('no check passed')
    if mode == 'gui':
        if not result.get('finished'):
            problems.append(f"the checks did not run to the end; last step: {result.get('step')}")
        unload = [event[0] for event in result.get('unload', [])]
        if with_settings and unload != EXPECTED_UNLOAD:
            problems.append(f'unexpected unload sequence on exit: {unload}')
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ida-dir', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--mode', choices=sorted(BINARIES), required=True)
    parser.add_argument('--without-settings', action='store_true',
                        help='GUI mode: start without stored settings to check the first-run path in batch mode')
    parser.add_argument('--seed-idausr', type=Path, default=Path.home() / '.idapro')
    parser.add_argument('--work-dir', type=Path, help='kept for inspection; a temporary directory otherwise')
    parser.add_argument('--timeout', type=int, default=240)
    arguments = parser.parse_args()

    with_settings = not arguments.without_settings
    work = arguments.work_dir or Path(tempfile.mkdtemp(prefix='threatray-ida-check-'))
    work.mkdir(parents=True, exist_ok=True)
    label = arguments.mode if with_settings else f'{arguments.mode}-without-settings'
    profile, result_file, log_file = work / f'idausr-{label}', work / f'{label}.json', work / f'{label}.log'
    for stale in (result_file, log_file):
        stale.unlink(missing_ok=True)
    prepare_profile(profile, arguments.seed_idausr.expanduser(), arguments.mode, with_settings)
    # a copy in an empty directory: IDA would otherwise reuse a database left beside the input
    session = Path(tempfile.mkdtemp(prefix='session-', dir=work))
    binary = shutil.copy2(arguments.input, session / arguments.input.name)

    environment = dict(os.environ, IDAUSR=str(profile), THREATRAY_REPOSITORY=str(REPOSITORY),
                       THREATRAY_CHECK_RESULT=str(result_file), THREATRAY_CHECK_SETTINGS='1' if with_settings else '0',
                       PYTHONUTF8='1',
                       # the checks use made-up settings, which must not reach the keychain of the machine
                       PYTHON_KEYRING_BACKEND='keyring.backends.null.Keyring')
    command = [str(find_binary(arguments.ida_dir, arguments.mode))]
    if environment.get('IDA_LICENSE'):
        command.append(f"-Olicense:{environment['IDA_LICENSE']}")
    command += ['-A', f'-L{log_file}', f"-S{REPOSITORY / 'tests' / 'ida' / f'{arguments.mode}_check.py'}", str(binary)]
    print('[ida-check]', label, ' '.join(a for a in command if not a.startswith('-Olicense:')), flush=True)

    try:
        completed = subprocess.run(command, env=environment, timeout=arguments.timeout, check=False,
                                   stdout=subprocess.DEVNULL if arguments.mode == 'headless' else None)
        exit_code = str(completed.returncode)
    except subprocess.TimeoutExpired:
        exit_code = f'none (killed after {arguments.timeout} s)'

    log = log_file.read_text(encoding='utf-8', errors='replace') if log_file.is_file() else ''
    if not result_file.is_file():
        print(log[-6000:])
        print(f'[ida-check] FAILED: IDA wrote no result (exit code {exit_code})')
        return 1
    print_stall_report(result_file.with_suffix('.stacks.txt'))
    result = json.loads(result_file.read_text(encoding='utf-8'))
    problems = evaluate(result, arguments.mode, with_settings)
    if any('threatray' in trace[:3000] for trace in log.split(TRACEBACK_MARKER)[1:]):
        problems.append('the IDA log contains a traceback that mentions the plugin')
    print(f"[ida-check] IDA {result.get('ida_version')} {label}: Qt binding {result.get('qt_binding', '-')}, "
          f"{len(result.get('passed', []))} checks passed, exit code {exit_code}")
    if result.get('selection_sources'):
        print(f"[ida-check] Functions window selection by source: {result['selection_sources']}")
    if problems:
        print(log[-6000:])
        for problem in problems:
            print(f'[ida-check] FAILED: {problem}')
        return 1
    print('[ida-check] OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
