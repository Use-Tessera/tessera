import init, { check, samples } from "./pkg/tessera_wasm.js";

// The group account in Tessera's test fixtures. Any G… address works.
const DEMO_ACCOUNT = "GAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSH7S";
const TESTNET_RPC = "https://soroban-testnet.stellar.org";

const $ = (id) => document.getElementById(id);
const policyEl = $("policy"), xdrEl = $("xdr"), accountEl = $("account"), ledgerEl = $("ledger");
const resultEl = $("result"), samplesEl = $("samples");
let examplePolicy = "";
let ready = false;
let timer;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const nowSecs = () => Math.floor(Date.now() / 1000);
const ledger = () => Number.parseInt(ledgerEl.value.replace(/[\s,]/g, ""), 10) || 0;
const show = (html) => { resultEl.innerHTML = html; };

const SAMPLE_NOTES = {
  "payment": "A 25 XLM payment that expires in five minutes.",
  "too-much": "150 XLM is over the example's 100 XLM per-transaction cap.",
  "no-expiry": "A transaction without time bounds would stay valid forever.",
  "merge": "account_merge would hand over the whole account.",
  "contract": "A SEP-41 transfer through a contract the policy allows.",
  "auth": "An authorization entry, the kind a relayer or x402 facilitator asks for. The example policy only signs these once you uncomment [auth].",
};

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(run, 120);
}

function run() {
  if (!ready) return;
  if (!xdrEl.value.trim()) {
    show(`<p class="muted">Pick an example above, or paste a base64 transaction envelope or Soroban authorization entry, to see what your signers would do.</p>`);
    return;
  }
  const r = JSON.parse(check(policyEl.value, xdrEl.value, accountEl.value, nowSecs(), ledger()));
  accountEl.setAttribute("aria-invalid", String(r.stage === "account"));
  if (!r.ok) return show(unreadable(r));
  const pressed = samplesEl.querySelector("[aria-pressed=true]");
  const note = pressed ? `<p class="muted">${esc(SAMPLE_NOTES[pressed.dataset.id] || "")}</p>` : "";
  const refused = r.violations.length > 0;
  let html = refused
    ? `<p class="verdict bad"><span class="mark" aria-hidden="true">✕</span>Signers would refuse</p>${note}
       <ul class="reasons">${r.violations.map((v) => `<li>${esc(v)}</li>`).join("")}</ul>`
    : `<p class="verdict"><span class="mark" aria-hidden="true">✓</span>Signers would sign</p>${note}`;
  html += r.kind === "transaction" ? describeTx(r.intent) : describeAuth(r.intent);
  if (r.spend.length) {
    html += `<h3>Counts toward limits</h3><dl class="facts">${r.spend.map((s) => `<dt>${esc(s.asset)}</dt><dd>${esc(s.amount)}</dd>`).join("")}</dl>`;
  }
  show(html);
}

function unreadable(r) {
  const where = { policy: "The policy can't be loaded", account: "The group account isn't valid", xdr: "This can't be decoded" }[r.stage];
  const next = {
    policy: `Fix it in the policy box, or <button type="button" class="link" data-reset>reset to the example</button>.`,
    account: "Use the G… address the signers' shares belong to.",
    xdr: "Paste the base64 XDR a wallet, SDK or <code>stellar tx</code> produces, or pick an example.",
  }[r.stage];
  return `<div class="reason"><strong>${esc(where)}:</strong> ${esc(r.error)}</div><p class="muted">${next}</p>`;
}

function describeTx(i) {
  const expiry = i.max_time == null ? "never" : `${new Date(i.max_time * 1000).toUTCString().replace("GMT", "UTC")} (${relative(i.max_time - nowSecs())})`;
  return `<h3>What it does</h3><dl class="facts">
      <dt>Source</dt><dd class="mono">${esc(i.source)}</dd>
      <dt>Fee</dt><dd>${i.fee.toLocaleString("en-US")} stroops${i.fee_bump ? " (fee bump)" : ""}</dd>
      <dt>Expires</dt><dd>${esc(expiry)}</dd></dl>
    <ol class="ops">${i.operations.map((o) => `<li><span class="tag">${esc(o.name)}</span>${esc(o.what)}${o.source ? ` <em>as ${esc(o.source)}</em>` : ""}</li>`).join("")}</ol>`;
}

function describeAuth(i) {
  const left = i.expiration_ledger - ledger();
  return `<h3>What it authorizes</h3><dl class="facts">
      <dt>For</dt><dd class="mono">${esc(i.address)}</dd>
      <dt>Expires</dt><dd>ledger ${i.expiration_ledger.toLocaleString("en-US")}${ledger() ? ` (${left > 0 ? `${left} ledgers, about ${relative(left * 5)}` : "already passed"})` : ""}</dd></dl>
    <ol class="ops">${i.calls.map((c) => `<li><span class="tag">${esc(c.name)}</span>${esc(c.what)}</li>`).join("")}</ol>`;
}

function relative(secs) {
  if (secs < 0) return "already passed";
  if (secs < 120) return `in ${secs} s`;
  if (secs < 7200) return `in ${Math.round(secs / 60)} min`;
  return `in ${Math.round(secs / 3600)} h`;
}

function loadSample(id) {
  const list = JSON.parse(samples(accountEl.value, nowSecs(), ledger()));
  if (list.error) {
    accountEl.setAttribute("aria-invalid", "true");
    show(`<div class="reason"><strong>The group account isn't valid:</strong> ${esc(list.error)}</div><p class="muted">Examples are built for the group account, so fix it first.</p>`);
    return;
  }
  xdrEl.value = list.find((s) => s.id === id).xdr;
  for (const b of samplesEl.children) b.setAttribute("aria-pressed", String(b.dataset.id === id));
  run();
}

function buttons() {
  const list = JSON.parse(samples(DEMO_ACCOUNT, nowSecs(), ledger()));
  samplesEl.innerHTML = list.map((s) => `<button type="button" data-id="${s.id}" aria-pressed="false">${esc(s.label)}</button>`).join("");
  samplesEl.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) loadSample(b.dataset.id); });
}

async function latestLedger() {
  try {
    const res = await fetch(TESTNET_RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getLatestLedger" }),
    });
    const seq = (await res.json()).result.sequence;
    if (!ledgerEl.value) ledgerEl.value = String(seq);
    $("ledger-hint").textContent = "Expiry is checked against the current time and testnet's latest ledger.";
  } catch {
    $("ledger-hint").textContent = "Couldn't reach testnet for the latest ledger; type it in to check authorization entries.";
  }
}

async function loadExample() {
  try {
    const res = await fetch("policy.toml");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    examplePolicy = await res.text();
  } catch {
    examplePolicy = "";
  }
  return examplePolicy;
}

document.addEventListener("click", (e) => {
  if (e.target.closest("#reset-policy, [data-reset]") && examplePolicy) { policyEl.value = examplePolicy; run(); }
});
xdrEl.addEventListener("input", () => { for (const b of samplesEl.children) b.setAttribute("aria-pressed", "false"); schedule(); });
for (const el of [policyEl, accountEl, ledgerEl]) el.addEventListener("input", schedule);

accountEl.value = DEMO_ACCOUNT;
const [example] = await Promise.all([loadExample(), latestLedger()]);
policyEl.value = example;
try {
  await init();
  ready = true;
  buttons();
  if (!example) show(`<div class="reason">The example policy couldn't be downloaded.</div><p class="muted">Paste your own <code>policy.toml</code> to start, or reload to try again.</p>`);
  else run();
} catch {
  show(`<div class="reason">The policy engine couldn't load, so nothing can be checked. Your browser may block WebAssembly; try reloading, or a current Chrome, Firefox or Safari.</div>`);
}
