// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"html/template"
	"net/http"
)

const signedOutPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Signed out · Shauth</title>
<link rel="stylesheet" href="/auth/gateway.css">
</head>
<body>
<main class="shell" id="main-content">
<section class="card" aria-labelledby="signed-out-title">
<span class="mark" aria-hidden="true">S</span>
<p class="eyebrow">Account security</p>
<h1 id="signed-out-title">Signed out</h1>
<p class="lede">Your Shauth single sign-on session and every connected application session have ended.</p>
<p class="actions"><a class="button" href="/auth/login">Sign in with Shauth</a></p>
</section>
</main>
</body>
</html>`

var validationPage = template.Must(template.New("validation").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Authentication validation · Shauth</title>
<link rel="stylesheet" href="/auth/gateway.css">
</head>
<body>
<main class="shell" id="main-content">
<section class="card" aria-labelledby="validation-title" data-auth-state="authenticated">
<span class="mark" aria-hidden="true">S</span>
<p class="eyebrow">Authentication validation</p>
<h1 id="validation-title">Signed in</h1>
<dl class="identity">
<dt>Username</dt><dd data-testid="validation-username">{{.Username}}</dd>
<dt>Email</dt><dd data-testid="validation-email">{{.Email}}</dd>
<dt>Role</dt><dd data-testid="validation-role">{{.Role}}</dd>
<dt>Release</dt><dd data-testid="validation-release"><code>{{.Release}}</code></dd>
</dl>
<form class="actions" method="post" action="/auth/logout"><button class="button" type="submit">Sign out</button></form>
</section>
</main>
</body>
</html>`))

const gatewayCSS = `:root{color-scheme:light dark;--bg:#f6f2ff;--surface:#fff;--ink:#211638;--muted:#625978;--border:#d8ccef;--violet:#7127e8;--violet-hover:#5916c7;--focus:#087f8c;--pink:#e62991;--shadow:0 24px 70px rgba(74,32,128,.18)}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 15%,#d9edff 0,transparent 32%),radial-gradient(circle at 85% 10%,#ffd5eb 0,transparent 34%),var(--bg);color:var(--ink);font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{min-height:100vh;display:grid;place-items:center;padding:2rem}.card{width:min(36rem,100%);padding:clamp(2rem,7vw,4rem);border:1px solid var(--border);border-radius:1.5rem;background:var(--surface);box-shadow:var(--shadow)}.mark{display:grid;place-items:center;width:3.5rem;height:3.5rem;margin-bottom:2rem;border-radius:1rem;background:linear-gradient(135deg,var(--violet),var(--pink));color:#fff;font-size:1.75rem;font-weight:800;box-shadow:0 12px 28px rgba(113,39,232,.3)}.eyebrow{margin:0 0 .7rem;color:#087f8c;font-weight:800;letter-spacing:.12em;text-transform:uppercase}h1{margin:0;font-size:clamp(2.5rem,9vw,4.5rem);line-height:1.02;letter-spacing:-.045em}.lede{margin:1.4rem 0 0;color:var(--muted);font-size:1.15rem;line-height:1.65}.identity{display:grid;grid-template-columns:max-content 1fr;gap:.65rem 1rem;margin:1.6rem 0 0}.identity dt{color:var(--muted);font-weight:700}.identity dd{margin:0;min-width:0;overflow-wrap:anywhere}.actions{margin:2rem 0 0}.button{display:inline-flex;min-height:3rem;align-items:center;justify-content:center;padding:.75rem 1.15rem;border:0;border-radius:.75rem;background:var(--violet);color:#fff;font:inherit;font-weight:750;line-height:1.25;text-decoration:none;cursor:pointer;box-shadow:0 10px 24px rgba(113,39,232,.24)}.button:hover{background:var(--violet-hover)}.button:focus-visible{outline:.2rem solid var(--focus);outline-offset:.2rem}@media(prefers-color-scheme:dark){:root{--bg:#100a1d;--surface:#1c132d;--ink:#faf7ff;--muted:#c8bedb;--border:#44345f;--violet:#9256f5;--violet-hover:#ad7aff;--focus:#55d9e7;--shadow:0 24px 70px rgba(0,0,0,.42)}body{background:radial-gradient(circle at 15% 15%,#12385a 0,transparent 32%),radial-gradient(circle at 85% 10%,#53203d 0,transparent 34%),var(--bg)}.button{color:#140722}}@media(prefers-reduced-motion:no-preference){.card{animation:arrive .35s ease-out both}@keyframes arrive{from{opacity:0;transform:translateY(.75rem)}to{opacity:1;transform:none}}}`

func gatewayStyles(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/css; charset=utf-8")
	response.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = response.Write([]byte(gatewayCSS))
}
