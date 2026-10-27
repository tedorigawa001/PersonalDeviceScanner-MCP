'use strict';
// End to end: pack and install the package the way a user gets it, then let the first
// `serve` set itself up and answer MCP. Installs packages from PyPI, so it is opt-in.
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..', '..');
const OPT_IN = process.env.PC_SCANNER_NPM_E2E === '1';
// CI's CPython 3.14 jobs must execute the hash check, including the tampered-lock test below.
const EXPECT_HASHED = process.env.PC_SCANNER_NPM_EXPECT_HASHED === '1';
const AUTO_DISCOVER = process.env.PC_SCANNER_NPM_AUTO_DISCOVER === '1';
// Printed when an environment is built: with hash checks, or with the versions only.
const SETUP_MESSAGE = /setting up Python|no lock was generated for Python/;

function run(command, args, options = {}) {
  const result = childProcess.spawnSync(command, args, { encoding: 'utf8', shell: process.platform === 'win32', ...options });
  assert.equal(result.status, 0, `${command} ${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

/** A minimal MCP client: newline-delimited JSON-RPC, where every stdout line must be a message. */
function connect(launcherPath, args, env) {
  const server = childProcess.spawn(process.execPath, [launcherPath, ...args], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  const stray = [];
  let stderr = '';
  server.stderr.setEncoding('utf8').on('data', (text) => { stderr += text; });
  readline.createInterface({ input: server.stdout }).on('line', (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      stray.push(line);
      return;
    }
    if (message.id !== undefined && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  });
  const exited = new Promise((resolve) => server.on('exit', (code, signal) => {
    // A server that stops early must fail the waiting requests, not leave them hanging.
    for (const [id, settle] of pending) settle({ id, error: { message: `server exited (${code ?? signal})`, stderr } });
    pending.clear();
    resolve({ code, signal });
  }));
  let next = 1;
  return {
    server,
    exited,
    stray,
    stderr: () => stderr,
    request(method, params) {
      const id = next++;
      server.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      return new Promise((resolve) => pending.set(id, resolve));
    },
    notify(method) {
      server.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`);
    },
  };
}

async function initialize(client) {
  const reply = await client.request('initialize', { protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'npm-roundtrip-test', version: '1' } });
  assert.equal(reply.result.serverInfo.name, 'Personal Device Scanner');
  client.notify('notifications/initialized');
}

test('the installed package sets itself up on first use and serves MCP on a clean stdout',
  { skip: !OPT_IN && 'set PC_SCANNER_NPM_E2E=1 to run (installs packages from PyPI)', timeout: 15 * 60 * 1000 },
  async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-scanner-npm-'));
    try {
      // From the packed tarball, so a file missing from "files" fails here.
      run('npm', ['pack', '--silent', '--ignore-scripts', '--pack-destination', work], { cwd: ROOT });
      const tarball = fs.readdirSync(work).find((name) => name.endsWith('.tgz'));
      const prefix = path.join(work, 'install');
      run('npm', ['install', '--prefix', prefix, '--ignore-scripts', '--no-audit', '--no-fund', path.join(work, tarball)]);
      const launcherPath = path.join(prefix, 'node_modules', 'personal-device-scanner-mcp', 'npm', 'launcher.js');
      const folder = path.join(work, 'scan');
      fs.mkdirSync(folder);
      fs.writeFileSync(path.join(folder, 'notes.txt'), 'nothing to see\n');
      const config = path.join(work, 'scanner.toml');
      fs.writeFileSync(config, `[scan_roots]\ndemo = ${JSON.stringify(folder)}\n`);
      const env = { ...process.env, PC_SCANNER_CACHE_DIR: path.join(work, 'cache') };
      // The hash-required CI jobs exercise the packed launcher's automatic search,
      // not just the explicit interpreter override used by the other jobs.
      if (AUTO_DISCOVER) delete env.PC_SCANNER_PYTHON;

      const client = connect(launcherPath, ['--config', config, 'serve'], env);
      await initialize(client);
      const tools = await client.request('tools/list', {});
      assert.deepEqual(tools.result.tools.map((tool) => tool.name).sort(),
        ['check_android_monitoring_apps', 'check_clamav_signatures', 'check_router', 'collect_android', 'collect_inventory', 'get_scan_progress', 'get_vulnerabilities',
          'scan_malware', 'scanner_status']);
      const status = await client.request('tools/call', { name: 'scanner_status', arguments: {} });
      const report = JSON.parse(status.result.content[0].text);
      assert.equal(report.status, 'completed');
      assert.deepEqual(report.data.scan_root_aliases, ['demo']);
      client.server.stdin.end();
      assert.deepEqual(await client.exited, { code: 0, signal: null });
      assert.deepEqual(client.stray, [], 'setup output must not reach the MCP channel');
      assert.match(client.stderr(), SETUP_MESSAGE);

      // Python runs isolated (-I): modules planted in the current folder are never imported.
      const planted = path.join(work, 'planted');
      const marker = path.join(work, 'planted-module-ran');
      fs.mkdirSync(planted);
      for (const module of ['json.py', 'venv.py', 'sysconfig.py', 'platform.py']) {
        fs.writeFileSync(path.join(planted, module), `open(${JSON.stringify(marker)}, "w").close()\n`);
      }
      const cli = childProcess.spawnSync(process.execPath, [launcherPath, '--config', config, 'status'],
        { cwd: planted, env, encoding: 'utf8' });
      assert.equal(cli.status, 0, cli.stderr);
      assert.equal(JSON.parse(cli.stdout).status, 'completed');
      assert.equal(fs.existsSync(marker), false, 'a module in the current folder was imported');

      // With a matching lock, pip enforces its hashes: one wrong hash stops the setup.
      const [built] = fs.readdirSync(env.PC_SCANNER_CACHE_DIR);
      const used = JSON.parse(fs.readFileSync(path.join(env.PC_SCANNER_CACHE_DIR, built, 'environment.json'), 'utf8'));
      if (EXPECT_HASHED) {
        assert.equal(used.hashed, true, 'CI requires a hash-checked installation; the tampered-lock test must not be skipped');
        assert.match(used.python, /^3\.14\./, 'the hash-required job must use the bundled CPython 3.14 profile');
        assert.match(client.stderr(), /with hash-checked packages/);
      }
      if (used.hashed) {
        const lock = path.join(prefix, 'node_modules', 'personal-device-scanner-mcp', used.lock);
        const original = fs.readFileSync(lock, 'utf8');
        fs.writeFileSync(lock, original.replace(/^(mcp==\S+ --hash=sha256:)[0-9a-f]{64}$/m, `$1${'0'.repeat(64)}`));
        const tampered = childProcess.spawnSync(process.execPath, [launcherPath, 'setup'],
          { env: { ...env, PC_SCANNER_CACHE_DIR: path.join(work, 'tampered-cache') }, encoding: 'utf8' });
        fs.writeFileSync(lock, original);
        assert.equal(tampered.status, 2, tampered.stderr);
        assert.match(tampered.stderr, /DO NOT MATCH THE HASHES/);
        assert.match(tampered.stderr, /Installing the packages failed/);
        assert.deepEqual(fs.readdirSync(path.join(work, 'tampered-cache')), [], 'a failed build leaves nothing behind');
      }

      if (process.platform !== 'win32') {
        // The environment is reused, and SIGTERM to the launcher stops the server too.
        const again = connect(launcherPath, ['--config', config, 'serve'], env);
        await initialize(again);
        assert.doesNotMatch(again.stderr(), SETUP_MESSAGE);
        const children = childProcess.spawnSync('pgrep', ['-P', String(again.server.pid)], { encoding: 'utf8' });
        const python = Number(children.stdout.trim().split('\n')[0]);
        assert.ok(python > 0, 'the server runs as a child of the launcher');
        again.server.kill('SIGTERM');
        assert.deepEqual(await again.exited, { code: null, signal: 'SIGTERM' });
        assert.throws(() => process.kill(python, 0), { code: 'ESRCH' });
      }
    } finally {
      fs.rmSync(work, { recursive: true, force: true });
    }
  });
