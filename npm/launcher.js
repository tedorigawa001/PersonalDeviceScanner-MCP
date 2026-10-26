#!/usr/bin/env node
'use strict';
// Starts the Python MCP server from a private virtual environment, which it builds on first
// use from the bundled lock files. It has no dependencies and no install scripts.
//
// stdout is the MCP channel, so everything this launcher and pip print goes to stderr.

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const NAME = 'personal-device-scanner-mcp';
const MINIMUM_PYTHON = [3, 11];
// Temporary build folders older than this were left by an interrupted setup.
const STALE_BUILD_MS = 24 * 60 * 60 * 1000;
const DESCRIBE = 'import json, platform, sys; print(json.dumps({"python": platform.python_version(), '
  + '"implementation": platform.python_implementation(), "os": platform.system(), '
  + '"architecture": platform.machine(), "executable": sys.executable}))';

class LauncherError extends Error {}

function log(message) {
  process.stderr.write(`${NAME}: ${message}\n`);
}

function packageVersion(root = PACKAGE_ROOT) {
  return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
}

/** The lock files bundled with the package, with the environment each was generated in. */
function readLocks(root = PACKAGE_ROOT) {
  const files = ['requirements-agent.lock'];
  const profiles = path.join(root, 'profiles');
  if (fs.existsSync(profiles)) {
    for (const name of fs.readdirSync(profiles).sort()) {
      const lock = path.join('profiles', name, 'requirements-agent.lock');
      if (fs.existsSync(path.join(root, lock))) files.push(lock);
    }
  }
  return files.map((file) => parseLock(file, fs.readFileSync(path.join(root, file), 'utf8')));
}

function parseLock(file, text) {
  const header = text.match(/^# Python\/OS: (\{.*\})$/m);
  if (!header) throw new LauncherError(`${file} does not record its Python/OS environment`);
  const pins = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Za-z0-9._-]+)==([^\s]+)(?: --hash=sha256:([0-9a-f]{64}))?$/);
    if (!match) throw new LauncherError(`${file} has an unexpected line: ${line}`);
    pins.push({ name: match[1], version: match[2], sha256: match[3] || null });
  }
  return { file, text, environment: JSON.parse(header[1]), pins };
}

function minorVersion(version) {
  return version.split('.').slice(0, 2).map(Number);
}

function supported(info) {
  const [major, minor] = minorVersion(info.python);
  return info.implementation === 'CPython'
    && (major > MINIMUM_PYTHON[0] || (major === MINIMUM_PYTHON[0] && minor >= MINIMUM_PYTHON[1]));
}

/**
 * Pick the interpreter and lock. Hashes are only checked when the lock was generated for the
 * same OS, CPU and Python minor version (the wheels differ otherwise); then the same versions
 * are installed without hash checks. Interpreters are tried in order, preferring a hash match.
 */
function chooseEnvironment(interpreters, locks) {
  const usable = interpreters.filter(supported);
  const same = (lock, info, keys) => keys.every((key) => lock.environment[key] === info[key]);
  for (const info of usable) {
    const lock = locks.find((candidate) => same(candidate, info, ['os', 'architecture', 'implementation'])
      && minorVersion(candidate.environment.python).join('.') === minorVersion(info.python).join('.')
      && candidate.pins.every((pin) => pin.sha256));
    if (lock) return { info, lock, hashed: true };
  }
  for (const info of usable) {
    const lock = locks.find((candidate) => same(candidate, info, ['os', 'architecture']))
      || locks.find((candidate) => same(candidate, info, ['os']));
    if (lock) return { info, lock, hashed: false };
  }
  return null;
}

function requirements(choice) {
  return choice.lock.pins.map((pin) => (choice.hashed ? `${pin.name}==${pin.version} --hash=sha256:${pin.sha256}`
    : `${pin.name}==${pin.version}`)).join('\n') + '\n';
}

function sourceFiles(root = PACKAGE_ROOT) {
  const folder = path.join(root, 'pc_scanner');
  return fs.readdirSync(folder).filter((name) => name.endsWith('.py')).sort()
    .map((name) => ({ name, data: fs.readFileSync(path.join(folder, name)) }));
}

/** Folder name for one environment: it changes whenever anything that went into it changes. */
function environmentName(choice, sources, version) {
  const digest = crypto.createHash('sha256');
  digest.update(JSON.stringify({ version, executable: choice.info.executable, python: choice.info.python,
    lock: choice.lock.text, hashed: choice.hashed }));
  for (const source of sources) digest.update(`\0${source.name}\0`).update(source.data);
  return `${version}-${digest.digest('hex').slice(0, 16)}`;
}

function cacheRoot(env = process.env, platform = process.platform, home = os.homedir()) {
  if (env.PC_SCANNER_CACHE_DIR) {
    if (!path.isAbsolute(env.PC_SCANNER_CACHE_DIR)) throw new LauncherError('PC_SCANNER_CACHE_DIR must be an absolute path');
    return env.PC_SCANNER_CACHE_DIR;
  }
  if (platform === 'win32') return path.join(env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), NAME);
  if (platform === 'darwin') return path.join(home, 'Library', 'Caches', NAME);
  return path.join(env.XDG_CACHE_HOME && path.isAbsolute(env.XDG_CACHE_HOME) ? env.XDG_CACHE_HOME
    : path.join(home, '.cache'), NAME);
}

/** Commands that may start Python, most specific first. */
function pythonCandidates(env = process.env, platform = process.platform) {
  if (env.PC_SCANNER_PYTHON) {
    if (!path.isAbsolute(env.PC_SCANNER_PYTHON)) throw new LauncherError('PC_SCANNER_PYTHON must be an absolute path');
    return [[env.PC_SCANNER_PYTHON]];
  }
  if (platform === 'win32') return [['py', '-3.15'], ['py', '-3.14'], ['py', '-3'], ['python']];
  return [['python3.15'], ['python3.14'], ['python3.13'], ['python3.12'], ['python3.11'], ['python3'], ['python']];
}

/**
 * The absolute path a command name resolves to, searching only the absolute folders on PATH.
 * Started by bare name, Windows looks in the current folder first, where a planted python.exe
 * would run; a relative PATH entry (".", or an empty one) does the same anywhere.
 */
function resolveOnPath(name, env = process.env, platform = process.platform) {
  const paths = platform === 'win32' ? path.win32 : path.posix;
  if (paths.isAbsolute(name)) return name;
  const entries = (env.PATH ?? env.Path ?? '').split(platform === 'win32' ? ';' : ':');
  const extensions = platform === 'win32' && !paths.extname(name) ? ['.exe', '.com'] : [''];
  for (const entry of entries) {
    if (!entry || !paths.isAbsolute(entry)) continue;
    for (const extension of extensions) {
      const candidate = paths.join(entry, name + extension);
      try {
        if (!fs.statSync(candidate).isFile()) continue;
        if (platform !== 'win32') fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      } catch {
        // not here
      }
    }
  }
  return null;
}

function probeOptions(env = process.env) {
  // Looking for Python must never install one: Windows' Python install manager installs a missing
  // runtime on its own when none is installed yet. Without Python the launcher stops and says so.
  return { encoding: 'utf8', timeout: 15000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
    env: { ...env, PYTHON_MANAGER_AUTOMATIC_INSTALL: 'false' } };
}

function describe(command, env = process.env, platform = process.platform) {
  const executable = resolveOnPath(command[0], env, platform);
  if (!executable) return null;
  // -I: ignore the current folder and PYTHON* variables, so nothing there can run.
  const result = childProcess.spawnSync(executable, [...command.slice(1), '-I', '-c', DESCRIBE], probeOptions(env));
  if (result.error || result.status !== 0) return null;
  try {
    const info = JSON.parse(result.stdout);
    return typeof info.executable === 'string' && path.isAbsolute(info.executable) ? info : null;
  } catch {
    return null;
  }
}

function venvPython(venv, platform = process.platform) {
  return platform === 'win32' ? path.join(venv, 'Scripts', 'python.exe') : path.join(venv, 'bin', 'python');
}

function check(command, args, what) {
  // Child output goes to stderr too: stdout stays clean for MCP.
  const result = childProcess.spawnSync(command, args, { stdio: ['ignore', 2, 2], windowsHide: true });
  if (result.error || result.status !== 0) {
    throw new LauncherError(`${what} failed${result.error ? `: ${result.error.message}` : ` (exit code ${result.status})`}`);
  }
}

function removeStaleBuilds(root, now = Date.now()) {
  for (const name of fs.readdirSync(root)) {
    if (!/^.+\.build-\d+-[0-9a-f]{8}$/.test(name)) continue;
    const folder = path.join(root, name);
    try {
      if (now - fs.statSync(folder).mtimeMs > STALE_BUILD_MS) fs.rmSync(folder, { recursive: true, force: true });
    } catch {
      // Another launcher may be cleaning up at the same time.
    }
  }
}

/** Build the environment in a temporary folder and move it into place when it is complete. */
function unhashedNote(choice, locks) {
  // Only a system and CPU with a hash-pinned lock has a CPython that installs with hash checks.
  const locked = locks.find((lock) => lock.environment.os === choice.info.os
    && lock.environment.architecture === choice.info.architecture && lock.pins.every((pin) => pin.sha256));
  return `no lock was generated for Python ${choice.info.python} on ${choice.info.os} ${choice.info.architecture}; `
    + `installing the versions in ${choice.lock.file} without hash checks`
    + (locked ? ` (use CPython ${minorVersion(locked.environment.python).join('.')} for hash-checked installs)` : '');
}

function build(choice, sources, root, name, locks = readLocks()) {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  removeStaleBuilds(root);
  const temporary = path.join(root, `${name}.build-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  const venv = path.join(temporary, 'venv');
  log(choice.hashed
    ? `setting up Python ${choice.info.python} with hash-checked packages from ${choice.lock.file} (first run only)`
    : unhashedNote(choice, locks));
  try {
    fs.mkdirSync(temporary, { mode: 0o700 });
    check(choice.info.executable, ['-I', '-m', 'venv', venv], 'Creating the virtual environment');
    const python = venvPython(venv);
    const lockCopy = path.join(temporary, 'requirements.txt');
    fs.writeFileSync(lockCopy, requirements(choice));
    check(python, ['-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--no-deps',
      '--only-binary=:all:', ...(choice.hashed ? ['--require-hashes'] : []), '-r', lockCopy], 'Installing the packages');
    check(python, ['-I', '-m', 'pip', 'check', '--disable-pip-version-check'], 'Checking the installed packages');
    const site = childProcess.spawnSync(python, ['-I', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
      { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 2] });
    if (site.status !== 0) throw new LauncherError('Locating the virtual environment failed');
    const target = path.join(site.stdout.trim(), 'pc_scanner');
    fs.mkdirSync(target);
    for (const source of sources) fs.writeFileSync(path.join(target, source.name), source.data);
    fs.writeFileSync(path.join(temporary, 'environment.json'), JSON.stringify({
      python: choice.info.python, executable: choice.info.executable, lock: choice.lock.file,
      hashed: choice.hashed }, null, 2) + '\n');
    try {
      fs.renameSync(temporary, path.join(root, name));
    } catch (error) {
      // Another launcher finished the same environment first; use that one.
      if (!fs.existsSync(path.join(root, name, 'environment.json'))) throw error;
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  } catch (error) {
    fs.rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
}

function findEnvironment(locks, env = process.env, platform = process.platform) {
  const interpreters = [];
  for (const command of pythonCandidates(env, platform)) {
    const info = describe(command, env, platform);
    if (!info) continue;
    interpreters.push(info);
    const alone = chooseEnvironment([info], locks);
    if (alone && alone.hashed) break; // no better interpreter to look for
  }
  return chooseEnvironment(interpreters, locks);
}

function main(argv = process.argv.slice(2)) {
  const locks = readLocks();
  const choice = findEnvironment(locks);
  if (!choice) {
    throw new LauncherError('CPython 3.11 or later is required. Install it from https://www.python.org/downloads/ '
      + 'or set PC_SCANNER_PYTHON to its absolute path.');
  }
  const sources = sourceFiles();
  const root = cacheRoot();
  const name = environmentName(choice, sources, packageVersion());
  if (!fs.existsSync(path.join(root, name, 'environment.json'))) build(choice, sources, root, name, locks);
  const python = venvPython(path.join(root, name, 'venv'));
  if (argv[0] === 'setup') {
    log(`ready: ${path.join(root, name)}`);
    return;
  }
  const child = childProcess.spawn(python, ['-I', '-m', 'pc_scanner.cli', ...argv], { stdio: 'inherit', windowsHide: true });
  // Ctrl+C reaches the server directly from the terminal; passing it on as well would interrupt
  // the server's own clean-up. SIGTERM and SIGHUP may be sent to this process alone.
  process.on('SIGINT', () => {});
  for (const signal of ['SIGTERM', 'SIGHUP']) process.on(signal, () => child.kill(signal));
  child.on('error', (error) => {
    log(`could not start the server: ${error.message}`);
    process.exit(2);
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
    } else {
      process.exit(code === null ? 2 : code);
    }
  });
}

module.exports = {
  LauncherError, cacheRoot, chooseEnvironment, describe, environmentName, findEnvironment, main, parseLock, probeOptions, pythonCandidates,
  readLocks, removeStaleBuilds, requirements, resolveOnPath, sourceFiles, supported, unhashedNote, venvPython,
};

if (require.main === module) {
  try {
    main();
  } catch (error) {
    log(error instanceof LauncherError ? error.message : `unexpected error: ${error.stack || error}`);
    process.exit(2);
  }
}
