import { afterAll, vi } from "vitest";

// A dialog that unmounts in a file's last test leaves a zero-delay timer behind (the focus scope
// returns focus on the next tick). If jsdom is torn down first, that timer dispatches an event built
// in a realm that no longer exists and Vitest reports an unhandled error against whichever file was
// running: every test passes and the run still fails, on a different file each time. Let pending
// zero-delay timers run before the environment goes away.
afterAll(async () => {
  vi.useRealTimers();
  await new Promise(resolve => setTimeout(resolve, 20));
});
