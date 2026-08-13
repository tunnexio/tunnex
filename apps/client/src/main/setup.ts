import { BRAND_WORDMARK_SVG } from "./brandmark";

// setupPageDataUrl builds the FIRST-RUN screen: a self-contained page (loaded as
// a data: URL, so it needs no bundled asset) that prompts for the server URL and
// hands it to main via the preload bridge. Main validates it against /healthz
// before accepting (the page just reports the outcome). It also surfaces the
// insecure-credential-storage state VISIBLY (decision (e)): if there is no OS
// keychain and no opt-in, the user is told login is blocked until they pass
// --allow-insecure-credential-storage (or use device-code, S6.2).
//
// ⛔ RESTYLED TO THE CLIENT, AND THE OLD PALETTE WAS NOT MERELY "OLD" — IT WAS A DIFFERENT THEME.
//
// It hardcoded `#7c5cff` for the primary button and `#0b0b12` for the page. Neither is the default
// theme: `--tnx-accent` is **`#C9C9C4`** and `--tnx-bg` is **`#0A0A0A`**. `#7C5CFC` is the accent of
// the `violet` theme — one the app does not select. So the first screen a user ever sees was
// painted from a palette the rest of the product never uses, which is why it read as a different
// application rather than as an older version of this one.
//
// > **A SURFACE OUTSIDE THE DESIGN SYSTEM DOES NOT AGE — IT DIVERGES.** This page cannot import
// > tokens (it is built before any bundle loads), so the values are transcribed with their token
// > names beside them, and the mark is embedded rather than skipped.
export function setupPageDataUrl(secureStorage: boolean, allowInsecure: boolean): string {
  const warn =
    !secureStorage && !allowInsecure
      ? `<p class="warn">No OS keychain is available on this system. Tunnex will NOT store a
         credential in plaintext. Re-launch with <code>--allow-insecure-credential-storage</code>
         to opt in explicitly, or use device-code login (coming in S6.2).</p>`
      : allowInsecure && !secureStorage
        ? `<p class="warn">Insecure credential storage is ENABLED (--allow-insecure-credential-storage):
           the credential will be written to disk without OS encryption.</p>`
        : "";
  const html = `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Tunnex — Setup</title>
<style>
  /* Values are the DEFAULT theme's, token name beside each one. */
  :root{
    --bg:#0A0A0A;            /* --tnx-bg */
    --line:#2E2E2E;          /* --tnx-border */
    --heading:#F5F5F5;       /* --tnx-text-heading */
    --body:#A9A9A6;          /* --tnx-text-body */
    --secondary:#858582;     /* --tnx-text-secondary */
    --warn:#C39A4E;          /* --tnx-warn */
    --danger:#C77474;        /* --tnx-danger */
    --focus:#C9C9C4;         /* --tnx-focus */
  }
  *{box-sizing:border-box}
  body{
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
    background:var(--bg);color:var(--body);margin:0;
    display:flex;justify-content:center;padding:1rem;min-height:100vh;
  }
  /* The client's card: 440px, 18px radius, one hairline, the same glass gradient. */
  .card{
    width:100%;max-width:440px;height:fit-content;display:flex;flex-direction:column;
    border:1px solid rgba(255,255,255,.14);border-radius:18px;
    background:linear-gradient(160deg,rgba(255,255,255,.06),transparent);
    padding:1.25rem;
  }
  .brand{display:flex;flex-direction:column;gap:.15rem;margin-bottom:1.5rem}
  .brand svg{width:112px;height:auto;display:block}  /* the wordmark is 792x120 — width-led */
  .tagline{font-size:8.5px;line-height:1.6;letter-spacing:.04em;color:var(--secondary)}
  h1{font-size:1.15rem;line-height:1.3;color:var(--heading);margin:0}
  .sub{font-size:.85rem;color:var(--secondary);margin:.35rem 0 0}
  label{display:block;font-size:.7rem;color:var(--secondary);margin:1.25rem 0 .35rem;
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;text-transform:uppercase}
  input{width:100%;padding:.6rem;border-radius:.5rem;border:1px solid var(--line);
        background:rgba(18,18,18,.72);color:var(--heading);font-size:.9rem}
  input:focus{outline:none;border-color:var(--focus)}
  button{margin-top:1rem;width:100%;padding:.7rem;border-radius:.5rem;
         border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.08);
         color:var(--heading);font-size:.85rem;font-weight:500;cursor:pointer}
  button:hover:not(:disabled){background:rgba(255,255,255,.14)}
  button:disabled{opacity:.6;cursor:default}
  .err{color:var(--danger);font-size:.75rem;margin-top:.6rem;min-height:1rem}
  .warn{color:var(--warn);font-size:.75rem;border:1px solid rgba(195,154,78,.4);
        background:rgba(195,154,78,.06);padding:.6rem;border-radius:.5rem;margin-top:1rem}
  code{background:rgba(255,255,255,.08);padding:.05rem .3rem;border-radius:.25rem}
</style></head>
<body><div class="card">
  <div class="brand">
    ${BRAND_WORDMARK_SVG}
    <span class="tagline">Connect Everything.<br>Trust Nothing.</span>
  </div>
  <h1>Connect to your Tunnex server</h1>
  <p class="sub">Enter the address of your self-hosted Tunnex control plane.</p>
  <label for="u">Server URL</label>
  <input id="u" type="url" placeholder="https://vpn.example.com" autofocus>
  <button id="go">Connect</button>
  <div class="err" id="err"></div>
  ${warn}
</div>
<script>
  const u = document.getElementById('u'), go = document.getElementById('go'), err = document.getElementById('err');
  go.onclick = async () => {
    err.textContent = ''; go.disabled = true; go.textContent = 'Checking…';
    try {
      await window.tunnex.config.setServerUrl(u.value);
      // main reloads the window into the SPA on success.
    } catch (e) {
      err.textContent = (e && e.message) ? e.message : 'Could not connect to that server.';
      go.disabled = false; go.textContent = 'Connect';
    }
  };
  u.addEventListener('keydown', (e) => { if (e.key === 'Enter') go.click(); });
</script>
</body></html>`;
  return "data:text/html;charset=utf-8," + encodeURIComponent(html);
}
