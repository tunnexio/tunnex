import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import type { Persistence } from "./credential";

const MAX_DURABLE_RECORD_BYTES = 1024 * 1024;

export interface DurableFileRuntime {
  platform: NodeJS.Platform;
  syncDirectory(directory: string): void;
}

const clearNamespaceReproofs = new WeakMap<DurableFileClearAfterUnlinkError, () => void>();

// Internal durability classification only. The unlink has already crossed the
// visible namespace boundary, but the parent-directory proof did not complete.
// Keep the error static: filesystem diagnostics and secret-bearing paths must
// never escape through the enrollment store or IPC.
export class DurableFileClearAfterUnlinkError extends Error {
  constructor() {
    super("durable_record_clear_unproved");
    this.name = "DurableFileClearAfterUnlinkError";
  }
}

// Consume the exact one-shot namespace capability created by clear(). This is
// deliberately separate from read(): a never-created parent is ordinary read
// absence, but a parent that disappears after unlink cannot prove an explicit
// confirmed removal.
export function reproveDurableFileClearNamespace(error: DurableFileClearAfterUnlinkError): void {
  const reprove = clearNamespaceReproofs.get(error);
  clearNamespaceReproofs.delete(error);
  if (!reprove) throw new DurableFileClearAfterUnlinkError();
  try {
    reprove();
  } catch {
    throw new DurableFileClearAfterUnlinkError();
  }
}

function isMissing(error: unknown): boolean {
  return !!error && typeof error === "object" && (error as NodeJS.ErrnoException).code === "ENOENT";
}

function syncDirectoryNative(directory: string): void {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function openPublishedFile(file: string): number {
  // O_RDWR is deliberate: Windows FlushFileBuffers may reject a read-only
  // handle even though the file itself is writable by this user.
  return fs.openSync(file, fs.constants.O_RDWR);
}

function syncPublishedFile(file: string): void {
  const descriptor = openPublishedFile(file);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function unsupportedWindowsDirectorySync(error: unknown, platform: NodeJS.Platform): boolean {
  if (platform !== "win32" || !error || typeof error !== "object") return false;
  const candidate = error as NodeJS.ErrnoException;
  return candidate.syscall === "fsync" && (candidate.code === "EPERM" || candidate.code === "EINVAL");
}

function syncNamespace(directory: string, runtime: DurableFileRuntime): void {
  try {
    runtime.syncDirectory(directory);
  } catch (error) {
    // Node/libuv can open a Windows directory but report FlushFileBuffers on
    // that directory handle as unsupported. Only that exact, platform-bound
    // class is a bounded fallback; ACL/open failures and every POSIX failure
    // remain fatal. The final file has already been reopened and synced.
    if (!unsupportedWindowsDirectorySync(error, runtime.platform)) throw error;
  }
}

const systemRuntime: DurableFileRuntime = {
  platform: process.platform,
  syncDirectory: syncDirectoryNative,
};

// buildDurableFilePersistence is the common publication primitive for a managed
// WireGuard identity. A write is visible only after a same-directory rename and
// both the file and containing namespace have been synchronized. Reads
// distinguish true absence from every other storage failure; callers therefore
// never turn an unreadable secret-bearing record into permission to enroll.
export function buildDurableFilePersistence(
  file: string,
  runtime: DurableFileRuntime = systemRuntime,
): Persistence {
  const directory = path.dirname(file);
  const basename = path.basename(file);
  return {
    read(): Buffer | null {
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(file);
      } catch (error) {
        if (isMissing(error)) {
          // An unlink may have become visible immediately before its namespace
          // sync failed. Re-prove the parent before treating that visible
          // absence as durable. A never-created parent is ordinary absence.
          try {
            const parent = fs.statSync(directory);
            if (!parent.isDirectory()) throw new Error("durable_record_invalid");
            syncNamespace(directory, runtime);
          } catch (parentError) {
            if (!isMissing(parentError)) throw parentError;
          }
          return null;
        }
        throw error;
      }
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_DURABLE_RECORD_BYTES) {
        throw new Error("durable_record_invalid");
      }
      // A prior write may have crossed rename and then failed its durability
      // proof. Reopen the exact visible final file, flush it, apply the same
      // namespace rule as publication, and read the encrypted bytes from that
      // synchronized handle. Store-level decryption/shape validation is the
      // second half of the trusted recovery read.
      const descriptor = openPublishedFile(file);
      try {
        const opened = fs.fstatSync(descriptor);
        if (!opened.isFile() || opened.size > MAX_DURABLE_RECORD_BYTES) {
          throw new Error("durable_record_invalid");
        }
        fs.fsyncSync(descriptor);
        syncNamespace(directory, runtime);
        const bytes = fs.readFileSync(descriptor);
        if (bytes.length !== opened.size) throw new Error("durable_record_invalid");
        return bytes;
      } finally {
        fs.closeSync(descriptor);
      }
    },
    write(bytes: Buffer): void {
      if (bytes.length > MAX_DURABLE_RECORD_BYTES) throw new Error("durable_record_too_large");
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const temporary = path.join(directory, `.${basename}.${process.pid}.${randomUUID()}.tmp`);
      let descriptor: number | null = null;
      try {
        descriptor = fs.openSync(
          temporary,
          fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
          0o600,
        );
        fs.writeFileSync(descriptor, bytes);
        fs.fsyncSync(descriptor);
        fs.closeSync(descriptor);
        descriptor = null;
        fs.renameSync(temporary, file);
        // A file-level FlushFileBuffers after the final name exists is common
        // across platforms. POSIX then also proves the directory namespace;
        // win32 permits only the exact unsupported directory-fsync class.
        syncPublishedFile(file);
        syncNamespace(directory, runtime);
      } catch (error) {
        if (descriptor !== null) {
          try { fs.closeSync(descriptor); } catch { /* preserve the publication error */ }
        }
        try { fs.rmSync(temporary); } catch { /* renamed or already absent */ }
        throw error;
      }
    },
    clear(): void {
      try {
        fs.lstatSync(file);
      } catch (error) {
        if (isMissing(error)) return;
        throw error;
      }
      const parentBefore = fs.statSync(directory);
      if (!parentBefore.isDirectory()) throw new Error("durable_record_invalid");
      try {
        fs.unlinkSync(file);
      } catch (error) {
        if (isMissing(error)) return;
        throw error;
      }
      try {
        syncNamespace(directory, runtime);
      } catch {
        const classified = new DurableFileClearAfterUnlinkError();
        clearNamespaceReproofs.set(classified, () => {
          const parent = fs.statSync(directory);
          if (
            !parent.isDirectory()
            || parent.dev !== parentBefore.dev
            || parent.ino !== parentBefore.ino
          ) throw new Error("durable_record_invalid");
          syncNamespace(directory, runtime);
        });
        throw classified;
      }
    },
  };
}
