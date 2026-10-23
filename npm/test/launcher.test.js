'use strict';
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const launcher = require('../launcher.js');

const ROOT = path.resolve(__dirname, '..', '..');
const LOCK_FILES = ['requirements-agent.lock', ...['darwin-arm64-cp314', 'linux-x86_64-cp314', 'windows-amd64-cp314']
  .map((name) => path.join('profiles', name, 'requirements-agent.lock'))];

function interpreter(os_, architecture, python, implementation = 'CPython') {
  return { os: os_, architecture, python, implementation, executable: '/opt/python/bin/python3' };
}

test('bundled locks record their environment and pin every package with a hash', () => {
  const locks = launcher.readLocks(ROOT);
  assert.deepEqual(locks.map((lock) => lock.file), LOCK_FILES);
  for (const lock of locks) {
    assert.ok(['Darwin', 'Linux', 'Windows'].includes(lock.environment.os), lock.file);
    assert.ok(lock.pins.length > 20, lock.file);
    assert.ok(lock.pins.every((pin) => /^[0-9a-f]{64}$/.test(pin.sha256)), lock.file);
  }
});

test('a lock line in an unexpected form is refused', () => {
  const header = '# Python/OS: {"os": "Linux", "architecture": "x86_64", "implementation": "CPython", "python": "3.14.8"}\n';
  assert.throws(() => launcher.parseLock('x.lock', `${header}mcp>=1.0\n`), launcher.LauncherError);
  assert.throws(() => launcher.parseLock('x.lock', 'mcp==1.30.0\n'), launcher.LauncherError);
  assert.throws(() => launcher.parseLock('x.lock', `${header}mcp==1.30.0 --index-url=https://example.com\n`),
    launcher.LauncherError);
});

test('CPython of the same OS, CPU and minor version gets hash-checked packages', () => {
  const locks = launcher.readLocks(ROOT);
  for (const lock of locks) {
    const { os: system, architecture } = lock.environment;
    const choice = launcher.chooseEnvironment([interpreter(system, architecture, '3.14.0')], locks);
    assert.equal(choice.lock, lock);
    assert.equal(choice.hashed, true);
  }
});

test('other Python versions and CPUs get the same versions without hash checks', () => {
  const locks = launcher.readLocks(ROOT);
  const older = launcher.chooseEnvironment([interpreter('Darwin', 'arm64', '3.12.9')], locks);
  assert.equal(older.lock.file, LOCK_FILES[1]);
  assert.equal(older.hashed, false);
  const arm = launcher.chooseEnvironment([interpreter('Linux', 'aarch64', '3.14.0')], locks);
  assert.equal(arm.lock.file, LOCK_FILES[2]);
  assert.equal(arm.hashed, false);
  assert.match(launcher.requirements(arm), /^mcp==1\.30\.0$/m);
  assert.doesNotMatch(launcher.requirements(arm), /--hash/);
  const latest = launcher.chooseEnvironment([interpreter('Darwin', 'x86_64', '3.15.1')], locks);
  assert.equal(latest.lock.file, LOCK_FILES[0]);
  assert.equal(latest.hashed, false); // Existing snapshots describe CPython 3.14 wheels.
  assert.match(launcher.requirements(launcher.chooseEnvironment([interpreter('Linux', 'x86_64', '3.14.8')], locks)),
    /^mcp==1\.30\.0 --hash=sha256:[0-9a-f]{64}$/m);
});

test('an interpreter that allows hash checks is preferred over an earlier one', () => {
  const locks = launcher.readLocks(ROOT);
  const choice = launcher.chooseEnvironment([interpreter('Linux', 'x86_64', '3.12.3'),
    interpreter('Linux', 'x86_64', '3.15.1'),
    interpreter('Linux', 'x86_64', '3.14.8')], locks);
  assert.equal(choice.info.python, '3.14.8');
  assert.equal(choice.hashed, true);
});

test('looking for Python never lets Windows install one', () => {
  // Found in the vulnerability check of 2026-10-24: the Python install manager installs a missing
  // runtime when none is installed yet, so probing `py -3.15` could install Python unasked.
  const options = launcher.probeOptions({ PATH: '/usr/bin', PYTHON_MANAGER_AUTOMATIC_INSTALL: 'true' });
  assert.equal(options.env.PYTHON_MANAGER_AUTOMATIC_INSTALL, 'false');
  assert.equal(options.env.PATH, '/usr/bin');
  assert.deepEqual(options.stdio, ['ignore', 'pipe', 'ignore']);
  assert.equal(options.timeout, 15000);
});

test('each interpreter is probed with those options', (context) => {
  const calls = [];
  context.mock.method(childProcess, 'spawnSync', (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: JSON.stringify({ python: '3.14.8', executable: path.resolve('/opt/python3') }) };
  });
  const probe = path.resolve('/opt/py');
  const info = launcher.describe([probe, '-3.15']);
  assert.equal(info.python, '3.14.8');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, probe);
  assert.deepEqual(calls[0].args.slice(0, 3), ['-3.15', '-I', '-c']);
  assert.equal(calls[0].options.env.PYTHON_MANAGER_AUTOMATIC_INSTALL, 'false');
});

test('the hint names a hash-checked CPython only where a lock exists', () => {
  const locks = launcher.readLocks(ROOT);
  const latest = launcher.chooseEnvironment([interpreter('Darwin', 'x86_64', '3.15.1')], locks);
  assert.match(launcher.unhashedNote(latest, locks), /without hash checks \(use CPython 3\.14 for hash-checked installs\)$/);
  // No lock for these CPUs, so no CPython would install with hash checks there.
  for (const [system, architecture] of [['Linux', 'aarch64'], ['Windows', 'ARM64']]) {
    const choice = launcher.chooseEnvironment([interpreter(system, architecture, '3.14.8')], locks);
    assert.equal(choice.hashed, false);
    const note = launcher.unhashedNote(choice, locks);
    assert.match(note, /without hash checks$/);
    assert.doesNotMatch(note, /use CPython/);
  }
});

test('unsupported interpreters and systems are refused', () => {
  const locks = launcher.readLocks(ROOT);
  assert.equal(launcher.chooseEnvironment([interpreter('Linux', 'x86_64', '3.10.14')], locks), null);
  assert.equal(launcher.chooseEnvironment([interpreter('Linux', 'x86_64', '3.14.0', 'PyPy')], locks), null);
  assert.equal(launcher.chooseEnvironment([interpreter('FreeBSD', 'amd64', '3.14.0')], locks), null);
  assert.equal(launcher.chooseEnvironment([], locks), null);
});

test('the environment folder changes with anything that goes into it', () => {
  const locks = launcher.readLocks(ROOT);
  const choice = launcher.chooseEnvironment([interpreter('Linux', 'x86_64', '3.14.8')], locks);
  const sources = launcher.sourceFiles(ROOT);
  const name = launcher.environmentName(choice, sources, '0.1.0');
  assert.match(name, /^0\.1\.0-[0-9a-f]{16}$/);
  assert.equal(launcher.environmentName(choice, sources, '0.1.0'), name);
  const changed = [
    launcher.environmentName(choice, sources, '0.1.1'),
    launcher.environmentName({ ...choice, info: { ...choice.info, python: '3.14.9' } }, sources, '0.1.0'),
    launcher.environmentName({ ...choice, lock: { ...choice.lock, text: `${choice.lock.text}\n` } }, sources, '0.1.0'),
    launcher.environmentName({ ...choice, hashed: false }, sources, '0.1.0'),
    launcher.environmentName(choice, [...sources.slice(1), { ...sources[0], data: Buffer.from('changed') }], '0.1.0'),
  ];
  assert.equal(new Set([name, ...changed]).size, changed.length + 1);
});

test('the cache folder follows each OS, and an override must be absolute', () => {
  const home = path.join(path.sep, 'home', 'someone');
  assert.equal(launcher.cacheRoot({}, 'darwin', home), path.join(home, 'Library', 'Caches', 'personal-device-scanner-mcp'));
  assert.equal(launcher.cacheRoot({}, 'linux', home), path.join(home, '.cache', 'personal-device-scanner-mcp'));
  assert.equal(launcher.cacheRoot({ XDG_CACHE_HOME: 'relative' }, 'linux', home),
    path.join(home, '.cache', 'personal-device-scanner-mcp'));
  assert.equal(launcher.cacheRoot({ LOCALAPPDATA: path.join(home, 'Local') }, 'win32', home),
    path.join(home, 'Local', 'personal-device-scanner-mcp'));
  assert.throws(() => launcher.cacheRoot({ PC_SCANNER_CACHE_DIR: 'cache' }, 'linux', home), launcher.LauncherError);
});

test('Python is found by fixed names, or only at an absolute path the owner set', () => {
  assert.deepEqual(launcher.pythonCandidates({}, 'win32').slice(0, 2), [['py', '-3.15'], ['py', '-3.14']]);
  assert.deepEqual(launcher.pythonCandidates({}, 'linux').slice(0, 2), [['python3.15'], ['python3.14']]);
  const absolute = path.resolve('opt', 'python3');
  assert.deepEqual(launcher.pythonCandidates({ PC_SCANNER_PYTHON: absolute }, 'linux'), [[absolute]]);
  assert.throws(() => launcher.pythonCandidates({ PC_SCANNER_PYTHON: 'python3' }, 'linux'), launcher.LauncherError);
});

test('Python is found only in absolute PATH folders, never in the current folder', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-scanner-path-'));
  const cwd = process.cwd();
  try {
    const name = process.platform === 'win32' ? 'python3.exe' : 'python3';
    const planted = path.join(base, 'planted');
    const real = path.join(base, 'real');
    for (const folder of [planted, real]) {
      fs.mkdirSync(folder);
      fs.writeFileSync(path.join(folder, name), '');
      fs.chmodSync(path.join(folder, name), 0o755);
    }
    process.chdir(planted);
    const delimiter = process.platform === 'win32' ? ';' : ':';
    // "." and an empty entry both mean the current folder; they are skipped.
    const env = { PATH: ['.', '', 'relative/bin', real].join(delimiter) };
    assert.equal(launcher.resolveOnPath('python3', env), path.join(real, name));
    assert.equal(launcher.resolveOnPath('python3', { PATH: ['.', ''].join(delimiter) }), null);
    assert.equal(launcher.resolveOnPath('python3', {}), null);
    const absolute = path.join(real, name);
    assert.equal(launcher.resolveOnPath(absolute, {}), absolute);
  } finally {
    process.chdir(cwd);
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test('on POSIX a file that is not executable is not Python', { skip: process.platform === 'win32' }, () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-scanner-path-'));
  try {
    fs.writeFileSync(path.join(folder, 'python3'), '');
    fs.chmodSync(path.join(folder, 'python3'), 0o644);
    assert.equal(launcher.resolveOnPath('python3', { PATH: folder }), null);
  } finally {
    fs.rmSync(folder, { recursive: true, force: true });
  }
});

test('only builds that were interrupted long ago are removed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-scanner-cache-'));
  try {
    const old = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    const names = { stale: '0.1.0-aaaaaaaaaaaaaaaa.build-123-0123abcd', fresh: '0.1.0-bbbbbbbbbbbbbbbb.build-456-89abcdef',
      ready: '0.1.0-cccccccccccccccc', other: 'notes.build-1-0123abcd.txt' };
    for (const name of Object.values(names)) fs.mkdirSync(path.join(root, name));
    for (const name of [names.stale, names.ready, names.other]) fs.utimesSync(path.join(root, name), old, old);
    launcher.removeStaleBuilds(root);
    assert.deepEqual(fs.readdirSync(root).sort(), [names.fresh, names.ready, names.other].sort());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('the npm package version matches the Python package', () => {
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  assert.equal(fs.readFileSync(path.join(ROOT, 'pyproject.toml'), 'utf8').match(/^version = "(.+)"$/m)[1], version);
  assert.equal(fs.readFileSync(path.join(ROOT, 'pc_scanner', '__init__.py'), 'utf8').match(/__version__ = "(.+)"/)[1],
    version);
});

test('the package holds only the launcher, the Python sources, the locks and the license', () => {
  const result = childProcess.spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'],
    { cwd: ROOT, encoding: 'utf8', shell: process.platform === 'win32' });
  assert.equal(result.status, 0, result.stderr);
  const files = JSON.parse(result.stdout)[0].files.map((file) => file.path).sort();
  const sources = fs.readdirSync(path.join(ROOT, 'pc_scanner')).filter((name) => name.endsWith('.py'))
    .map((name) => `pc_scanner/${name}`);
  assert.deepEqual(files, ['LICENSE', 'README.ja.md', 'README.md', 'npm/launcher.js', 'package.json', ...sources,
    ...LOCK_FILES.map((file) => file.split(path.sep).join('/'))].sort());
});
