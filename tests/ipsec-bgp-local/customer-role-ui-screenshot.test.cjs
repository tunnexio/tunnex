const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { capturePrivateScreenshot } = require('./customer-role-ui-screenshot.cjs');

const image = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0xff]);

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'tunnex-screenshot-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { directory, file: path.join(directory, 'capture.png') };
}

function page(capture = async () => image) {
  return {
    screenshot(options) {
      assert.deepEqual(options, { type: 'png', fullPage: true });
      return capture();
    },
  };
}

function watchDescriptors(t) {
  const operations = [];
  for (const method of ['openSync', 'writeFileSync', 'fsyncSync', 'closeSync']) {
    const original = fs[method];
    t.mock.method(fs, method, (...args) => {
      const result = original(...args);
      operations.push({ method, args, result });
      return result;
    });
  }
  return operations;
}

test('buffer capture creates private content and flushes its descriptor and directory', async t => {
  const { directory, file } = fixture(t);
  const operations = watchDescriptors(t);
  assert.equal(await capturePrivateScreenshot(page(), file), file);
  assert.deepEqual(fs.readFileSync(file), image);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);

  // The browser gets no path. The file is opened only once, and a receipt can
  // observe success only after both the file and its directory are flushed.
  const creation = operations[0];
  assert.equal(creation.method, 'openSync');
  assert.equal(creation.args[0], file);
  assert.equal(creation.args[1], fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW);
  assert.equal(creation.args[2], 0o600);
  assert.deepEqual(operations.slice(1, 4).map(op => [op.method, op.args[0]]), [
    ['writeFileSync', creation.result],
    ['fsyncSync', creation.result],
    ['closeSync', creation.result],
  ]);
  const directoryOpen = operations[4];
  assert.equal(directoryOpen.method, 'openSync');
  assert.equal(directoryOpen.args[0], directory);
  assert.deepEqual(operations.slice(5, 7).map(op => [op.method, op.args[0]]), [
    ['fsyncSync', directoryOpen.result],
    ['closeSync', directoryOpen.result],
  ]);
  assert.equal(operations.filter(op => op.method === 'writeFileSync').length, 1);
});

for (const kind of ['file', 'symlink']) {
  test(`existing ${kind} is refused without changing its content or permissions`, async t => {
    const { directory, file } = fixture(t);
    const target = kind === 'file' ? file : path.join(directory, 'original.png');
    fs.writeFileSync(target, 'untouched', { mode: 0o640 });
    const targetFD = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    t.after(() => fs.closeSync(targetFD));
    const original = fs.fstatSync(targetFD);
    if (kind === 'symlink') fs.symlinkSync(target, file);
    await assert.rejects(capturePrivateScreenshot(page(), file), { code: 'EEXIST' });
    assert.equal(fs.readFileSync(targetFD, 'utf8'), 'untouched');
    assert.equal(fs.fstatSync(targetFD).mode & 0o777, original.mode & 0o777);
    const current = fs.lstatSync(target);
    assert.equal(current.dev, original.dev);
    assert.equal(current.ino, original.ino);
    if (kind === 'symlink') assert.equal(fs.readlinkSync(file), target);
  });

  test(`${kind} created while capture is awaiting is refused without overwrite`, async t => {
    const { directory, file } = fixture(t);
    let release;
    const captured = new Promise(resolve => { release = resolve; });
    const pending = capturePrivateScreenshot(page(() => captured), file);
    const target = kind === 'file' ? file : path.join(directory, 'racing.png');
    fs.writeFileSync(target, 'racing owner', { mode: 0o640 });
    const targetFD = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    t.after(() => fs.closeSync(targetFD));
    const original = fs.fstatSync(targetFD);
    if (kind === 'symlink') fs.symlinkSync(target, file);
    release(image);
    await assert.rejects(pending, { code: 'EEXIST' });
    assert.equal(fs.readFileSync(targetFD, 'utf8'), 'racing owner');
    assert.equal(fs.fstatSync(targetFD).mode & 0o777, original.mode & 0o777);
    const current = fs.lstatSync(target);
    assert.equal(current.dev, original.dev);
    assert.equal(current.ino, original.ino);
    if (kind === 'symlink') assert.equal(fs.readlinkSync(file), target);
  });
}

test('capture rejection creates no output or descriptor', async t => {
  const { directory, file } = fixture(t);
  const failure = new Error('capture refused');
  const operations = watchDescriptors(t);
  await assert.rejects(capturePrivateScreenshot(page(async () => { throw failure; }), file), error => error === failure);
  assert.equal(operations.length, 0);
  assert.deepEqual(fs.readdirSync(directory), []);
});

for (const phase of ['write', 'file sync', 'directory sync']) {
  test(`${phase} failure closes every acquired descriptor and rejects publication`, async t => {
    const { file } = fixture(t);
    const opened = [];
    const closed = [];
    const open = fs.openSync;
    const close = fs.closeSync;
    const sync = fs.fsyncSync;
    const failure = new Error(`${phase} refused`);
    t.mock.method(fs, 'openSync', (...args) => {
      const fd = open(...args);
      opened.push(fd);
      return fd;
    });
    t.mock.method(fs, 'closeSync', fd => {
      close(fd);
      closed.push(fd);
    });
    if (phase === 'write') {
      t.mock.method(fs, 'writeFileSync', () => { throw failure; });
    } else {
      t.mock.method(fs, 'fsyncSync', fd => {
        if ((phase === 'file sync' && opened.length === 1) ||
            (phase === 'directory sync' && opened.length === 2)) throw failure;
        return sync(fd);
      });
    }
    await assert.rejects(capturePrivateScreenshot(page(), file), error => error === failure);
    assert.equal(opened.length, phase === 'directory sync' ? 2 : 1);
    assert.deepEqual(closed, opened);
    for (const fd of opened) assert.throws(() => fs.fstatSync(fd), { code: 'EBADF' });
  });
}
