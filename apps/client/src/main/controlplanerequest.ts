export const CONTROL_PLANE_REQUEST_TIMEOUT_MS = 15_000;

// One deadline owns both header arrival and response consumption. Returning a
// raw Response would clear the timer too early and let a stalled body keep a
// managed-lifecycle FIFO turn forever.
export async function controlPlaneRequest<T>(
  input: string | URL,
  init: RequestInit,
  consume: (response: Response) => Promise<T>,
  timeoutMs = CONTROL_PLANE_REQUEST_TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  let timeout: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(new Error("control_plane_request_timeout"));
    }, timeoutMs);
  });
  const request = (async () => {
    const response = await fetch(input, { ...init, signal: controller.signal });
    return consume(response);
  })();
  try {
    return await Promise.race([request, deadline]);
  } catch (error) {
    if (timedOut) throw new Error("control_plane_request_timeout");
    throw error;
  } finally {
    clearTimeout(timeout!);
  }
}
