// Disposable VM OS-resolver canary only. No third-party modules or onward dial.
'use strict';
process.on('uncaughtException', () => process.exit(77));
process.on('unhandledRejection', () => process.exit(77));
if (process.platform !== 'darwin' || !process.getuid || process.getuid() < 500 ||
    process.getuid() !== process.geteuid() || process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.PROXYPILOT_VM_GOST_RESOLVER_TESTS !== '1' ||
    process.env.PROXYPILOT_VM_GOST_SYSTEM_RESOLVER_TESTS !== '1' || process.argv.length !== 3) process.exit(77);
const fs = require('node:fs');
const path = require('node:path');
const configPath = process.argv[2];
const folder = path.dirname(configPath);
const root = fs.realpathSync(process.env.RUNNER_TEMP);
const info = fs.lstatSync(folder), configInfo = fs.lstatSync(configPath);
if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700 ||
    !fs.realpathSync(folder).startsWith(root + path.sep) || !configInfo.isFile() ||
    configInfo.nlink !== 1 || configInfo.uid !== process.getuid() || (configInfo.mode & 0o777) !== 0o600 ||
    configInfo.size > 1024) process.exit(77);
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const modes = ['in-cidr', 'out-cidr'];
if (!modes.includes(config.mode) || !/^(udp|tcp)\.pp-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.test$/.test(config.host)) process.exit(77);
const socketPath = path.join(folder, 'resolver.sock');
if (Buffer.byteLength(socketPath) >= 100 || fs.existsSync(socketPath)) process.exit(77);
const witness = fs.openSync(path.join(folder, 'events.jsonl'), 'wx', 0o600);
const http2 = require('node:http2');
const server = http2.createServer();
const sessions = new Set();
let count = 0;
function number(bytes, state) {
  let value = 0, shift = 0;
  for (let i = 0; i < 5; i++) {
    if (state.offset >= bytes.length) throw 0;
    const b = bytes[state.offset++]; value += (b & 127) * (2 ** shift);
    if (!(b & 128)) return value;
    shift += 7;
  }
  throw 0;
}
function request(bytes) {
  if (bytes.length < 5 || bytes.length > 1029 || bytes[0] !== 0 || bytes.readUInt32BE(1) !== bytes.length - 5) throw 0;
  const fields = {}, state = {offset: 5};
  while (state.offset < bytes.length) {
    const tag = number(bytes, state), length = number(bytes, state);
    if (![10, 18, 26].includes(tag) || Object.hasOwn(fields, tag) || length > 512 || state.offset + length > bytes.length) throw 0;
    fields[tag] = bytes.subarray(state.offset, state.offset + length).toString('utf8'); state.offset += length;
  }
  if (fields[10] !== 'ip' || fields[18] !== config.host) throw 0;
}
function reply(ip) {
  const body = Buffer.concat([Buffer.from([10, Buffer.byteLength(ip)]), Buffer.from(ip), Buffer.from([16, 1])]);
  const frame = Buffer.alloc(5); frame.writeUInt32BE(body.length, 1);
  return Buffer.concat([frame, body]);
}
server.on('error', () => process.exit(77));
server.on('session', session => {
  sessions.add(session); session.on('error', () => {});
  session.on('close', () => sessions.delete(session)); session.setTimeout(3000, () => session.destroy());
});
server.on('stream', (stream, headers) => {
  stream.on('error', () => {});
  let chunks = [], size = 0;
  stream.on('data', chunk => { size += chunk.length; if (size > 1029) stream.close(); else chunks.push(chunk); });
  stream.on('end', async () => {
    if (++count > 4) process.exit(77);
    let valid = false;
    try { request(Buffer.concat(chunks)); valid = headers[':path'] === '/proto.Resolver/Resolve' && headers[':method'] === 'POST'; } catch {}
    const token = headers.token === 'owned-synthetic-token';
    let ip, resolved = false, timer;
    // Only a fully authenticated, bounded, exact synthetic question reaches OS DNS.
    if (valid && token) {
      try {
        const family = config.mode === 'in-cidr' ? 4 : 6;
        const result = await Promise.race([
          require('node:dns').promises.lookup(config.host + '.', {family, all: true, verbatim: true}),
          new Promise((_, reject) => { timer = setTimeout(() => reject(0), 2000); })
        ]);
        const expected = family === 4 ? '127.0.0.1' : '::1';
        if (!Array.isArray(result) || result.length !== 1 || result[0].family !== family || result[0].address !== expected) throw 0;
        ip = expected; resolved = true;
      } catch {} finally { clearTimeout(timer); }
    }
    fs.writeSync(witness, JSON.stringify({valid, token, resolved}) + '\n');
    const status = !valid || !token ? '16' : resolved ? '0' : '14';
    stream.respond({':status': 200, 'content-type': 'application/grpc'}, {waitForTrailers: true});
    stream.on('wantTrailers', () => stream.sendTrailers({'grpc-status': status}));
    stream.end(status === '0' ? reply(ip) : undefined);
  });
});
server.listen(socketPath, () => { fs.chmodSync(socketPath, 0o600); process.stdout.write('READY\n'); });
process.on('SIGTERM', () => {
  for (const session of sessions) session.destroy();
  server.close(() => { fs.closeSync(witness); process.exit(0); });
  setTimeout(() => process.exit(77), 500).unref();
});
