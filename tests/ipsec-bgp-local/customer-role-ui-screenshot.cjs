const fs = require('node:fs');
const path = require('node:path');

// Capture in memory: the browser never checks or writes the output path.
// Exclusive creation owns one descriptor through write and durable flush.
async function capturePrivateScreenshot(page, file) {
  const image = await page.screenshot({ type: 'png', fullPage: true });
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(fd, image);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY |
    fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try {
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(directory);
  }
  return file;
}

module.exports = { capturePrivateScreenshot };
