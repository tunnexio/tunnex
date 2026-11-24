// SA-UX-2 item 7: notice when the control plane that served this page now serves a newer dashboard build.
// Same-origin only: the page compares the module script its own /index.html references with the one it loaded.
// No phone-home, no new endpoint. index.html is served with Cache-Control: no-cache (deploy/nginx/spa.conf).

/** The hashed entry script an index document references, e.g. /assets/index-abc123.js. */
export function entryScript(html: string): string | null {
  const match = /<script[^>]*type=["']module["'][^>]*src=["']([^"']+)["']/i.exec(html) ?? /<script[^>]*src=["']([^"']+)["'][^>]*type=["']module["']/i.exec(html);
  return match?.[1] ?? null;
}

export function loadedEntryScript(doc: Document = document): string | null {
  const script = doc.querySelector<HTMLScriptElement>('script[type="module"][src]');
  if (!script) return null;
  try { return new URL(script.src, doc.baseURI).pathname; } catch { return script.getAttribute("src"); }
}

/** True only when both are known and differ; any failure means "no news" rather than a false alarm. */
export async function newerBuildAvailable(fetcher: typeof fetch = fetch, loaded = loadedEntryScript()): Promise<boolean> {
  if (!loaded || !loaded.startsWith("/assets/")) return false; // dev server or unknown layout
  try {
    const response = await fetcher("/index.html", { cache: "no-store", credentials: "same-origin", headers: { Accept: "text/html" } });
    if (!response.ok) return false;
    const served = entryScript(await response.text());
    if (!served) return false;
    let path = served;
    try { path = new URL(served, window.location.origin).pathname; } catch { /* keep as is */ }
    return path.startsWith("/assets/") && path !== loaded;
  } catch {
    return false;
  }
}
