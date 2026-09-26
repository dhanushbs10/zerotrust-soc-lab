/* ZeroTrust SOC console -- client
   ------------------------------------------------------------------
   No framework, no build step, no npm. The project has deliberately avoided
   a Node toolchain so far and there is no reason a status page should be the
   thing that introduces one.

   Everything renders from the read APIs; the control panel POSTs to the
   action allowlist and polls the job. Nothing here computes a verdict the
   server did not compute -- in particular the "uncovered" panel is exactly
   what /api/summary reports, and this file does not try to be cleverer than
   the thing it is displaying. */

'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  rules: [],
  selectedRule: null,
  jobs: new Map(),
  pollTimer: null,
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

function toast(msg, bad = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('is-bad', bad);
  el.classList.add('is-on');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('is-on'), 4200);
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body = null;
  try { body = await res.json(); } catch { /* empty or non-JSON */ }
  return { status: res.status, ok: res.ok, body };
}

const ago = (secs) => {
  if (secs == null) return '—';
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86400)}d`;
};

const bytes = (n) => {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
};

/* ── tabs ─────────────────────────────────────────────────── */

$$('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    $$('.tab').forEach((t) => t.classList.toggle('is-active', t === tab));
    $$('.view').forEach((v) => v.classList.toggle('is-active', v.dataset.view === tab.dataset.view));
    if (tab.dataset.view === 'detections' && !state.rules.length) loadDetections();
    if (tab.dataset.view === 'graph') loadGraph();
    if (tab.dataset.view === 'chain') loadChain();
    if (tab.dataset.view === 'stream') loadStream();
    if (tab.dataset.view === 'control') loadActions();
  });
});

/* ── health + overview ─────────────────────────────────────── */

async function loadHealth() {
  const { body } = await api('/api/health');
  if (!body) return;
  const pill = $('#cluster-pill');
  const ready = body.cluster === 'ready';
  pill.textContent = `cluster ${body.cluster}`;
  pill.className = `pill ${ready ? 'pill-ok' : 'pill-bad'}`;

  const files = Object.entries(body.artifacts || {})
    .sort((a, b) => b[1].ageSeconds - a[1].ageSeconds);
  const oldest = files.length ? Math.max(...files.map((f) => f[1].ageSeconds)) : null;

  $('#stamp').textContent = `refreshed ${new Date().toLocaleTimeString()}`;

  const tb = $('#artifacts tbody');
  if (!files.length) {
    tb.innerHTML = '<tr><td colspan="3" class="empty">no artifacts yet — run a collection from Control</td></tr>';
    return;
  }
  tb.innerHTML = files.map(([name, info]) => {
    const stale = info.ageSeconds > 3600;
    return `<tr>
      <td class="mono">${esc(name)}</td>
      <td class="num dim">${bytes(info.bytes)}</td>
      <td class="num ${stale ? 'hit-0' : 'dim'}">${ago(info.ageSeconds)}</td>
    </tr>`;
  }).join('');

  if (oldest != null && oldest > 3600) {
    toast(`oldest artifact is ${ago(oldest)} old`, true);
  }
}

async function loadOverview() {
  const { body } = await api('/api/summary');
  if (!body) return;

  // Privilege paths
  const w = body.walks || {};
  const setTile = (key, value, note, status) => {
    $(`#t-${key}`).textContent = value;
    $(`#tn-${key}`).textContent = note;
    $(`.tile[data-k="${key === 'detect' ? 'detect' : key}"]`)?.setAttribute('data-s', status);
  };
  if (w.paths) {
    const held = w.held ?? 0;
    const failed = w.failed ?? 0;
    setTile('walks', `${held}/${held + failed}`,
      `${w.paths} paths · ${(w.attackIds || []).length} techniques`,
      failed ? 'bad' : 'ok');
  } else {
    setTile('walks', '—', 'no sweep recorded', 'warn');
  }

  // Chain
  const c = body.chain || {};
  if (c.run) {
    const undet = (c.undetectable || []).length;
    setTile('chain', `${c.succeeded}/${(c.succeeded || 0) + (c.failed || 0)}`,
      undet ? `${undet} hop(s) undetectable` : 'every hop has a rule',
      c.failed ? 'bad' : undet ? 'warn' : 'ok');
  } else {
    setTile('chain', '—', 'no chain recorded', 'warn');
  }

  // Detections
  setTile('detect', '…', 'loading rules', 'warn');
  const det = await api('/api/detections');
  if (det.body && det.body.rules) {
    const rules = det.body.rules;
    const total = rules.reduce((a, r) => a + (r.hits || 0), 0);
    const dead = rules.filter((r) => (r.hits || 0) === 0).length;
    setTile('detect', String(rules.length),
      dead ? `${dead} rule(s) matched nothing` : `${total} event(s) matched`,
      dead ? 'bad' : 'ok');
  }

  // Graph
  const g = body.graph || {};
  if (g.edges != null) {
    setTile('graph', String(g.edges), `${g.nodes ?? '?'} nodes modelled`, 'ok');
  } else {
    setTile('graph', '—', 'no graph recorded', 'warn');
  }

  renderGaps(c);
  loadCoverage();
}

function renderGaps(chain) {
  const host = $('#gaps');
  const undet = chain?.undetectable || [];
  if (!undet.length) { host.innerHTML = ''; return; }
  host.innerHTML = undet.map((t) => `
    <div class="gap">
      <div class="gap-t">${esc(t)}</div>
      <div class="gap-d">No collected schema carries this technique, so no rule can
        fire on the behaviour. The hop still ran. This is a gap in what the lab
        collects, not in the rules.</div>
    </div>`).join('');
}

async function loadCoverage() {
  const { body } = await api('/api/attack-coverage');
  const host = $('#coverage');
  if (!body || body._missing) { host.innerHTML = '<p class="empty">no coverage report</p>'; return; }

  const rows = body.schemas || body.coverage || [];
  if (!Array.isArray(rows) || !rows.length) {
    host.innerHTML = '<p class="empty">coverage report has no per-schema rows</p>';
    return;
  }
  const max = Math.max(...rows.map((r) => r.observed || 0), 1);
  host.innerHTML = rows.map((r) => {
    const n = r.observed || 0;
    const pct = Math.round((n / max) * 100);
    const tech = (r.techniques || []).map((t) => `<span class="chip chip-t">${esc(t)}</span>`).join('');
    return `<div class="cov" title="${esc(r.schema)}">
      <span class="cov-id">${esc((r.techniques || [])[0] || r.schema.split('/')[1] || '')}</span>
      <span><span class="cov-bar"><span class="cov-fill ${n ? '' : 'zero'}" style="width:${pct}%"></span></span>
        <span class="dim mono" style="font-size:11px">${esc(r.schema)}</span></span>
      <span class="cov-n">${n}</span>
    </div>${tech ? '' : ''}`;
  }).join('');
}

/* ── detections ───────────────────────────────────────────── */

async function loadDetections() {
  const { body } = await api('/api/detections');
  if (!body) return;
  state.rules = body.rules || [];

  const tb = $('#rules tbody');
  if (!state.rules.length) {
    tb.innerHTML = '<tr><td colspan="4" class="empty">no rules found</td></tr>';
    return;
  }
  tb.innerHTML = state.rules.map((r, i) => {
    if (r._broken) {
      return `<tr><td class="mono">${esc(r._broken)}</td>
        <td colspan="3" class="dim">failed to load: ${esc(r._error)}</td></tr>`;
    }
    const tech = (r.techniques || []).map((t) => `<span class="chip chip-t">${esc(t)}</span>`).join('');
    const cls = r.hits === 0 ? 'hit-0' : r.hits < 20 ? 'hit-lo' : 'hit-hi';
    return `<tr data-i="${i}">
      <td>${esc(r.title)}<div class="dim mono" style="font-size:11px">${esc(r.id || '')}</div></td>
      <td>${tech}</td>
      <td class="num"><span class="hit ${cls}">${r.hits}</span></td>
      <td class="mono dim" style="font-size:11px">${esc(r.schema || '')}</td>
    </tr>`;
  }).join('');

  $$('#rules tbody tr').forEach((tr) => tr.addEventListener('click', () => {
    $$('#rules tbody tr').forEach((x) => x.classList.remove('is-sel'));
    tr.classList.add('is-sel');
    showSamples(Number(tr.dataset.i));
  }));

  if (state.rules.length) showSamples(0);
}

function showSamples(i) {
  const r = state.rules[i];
  const host = $('#samples');
  if (!r || !r.sample || !r.sample.length) {
    host.innerHTML = '<p class="empty">this rule matched nothing, so there is nothing to show</p>';
    return;
  }
  host.innerHTML = r.sample.map((s) => `
    <div style="padding:8px 0;border-bottom:1px solid var(--line-soft)">
      <div class="mono dim" style="font-size:11px">${esc(s.collectedAt || '')}</div>
      <div class="mono" style="font-size:12px;margin-top:2px">${esc(s.summary || '')}</div>
      <div style="margin-top:3px">${(s.techniqueIds || []).map((t) => `<span class="chip">${esc(t)}</span>`).join('')}</div>
    </div>`).join('');
}

/* ── graph ────────────────────────────────────────────────── */

async function loadGraph() {
  const { body } = await api('/api/graph');
  const host = $('#graph');
  if (!body || body._missing) { host.innerHTML = '<p class="empty">no reachability graph recorded</p>'; return; }

  const edges = body.edges || [];
  if (!edges.length) { host.innerHTML = '<p class="empty">graph has no edges</p>'; return; }

  // Sort open first: the interesting pairs are the ones an attacker would use.
  const rank = (e) => (e.observed === 'open' ? 0 : e.noListener ? 1 : 2);
  const sorted = edges.slice().sort((a, b) => rank(a) - rank(b));

  host.innerHTML = sorted.map((e) => {
    const open = e.observed === 'open';
    const cls = open ? 'open' : e.noListener ? 'nolistener' : '';
    const verdict = open ? 'open' : e.noListener ? 'no listener' : 'blocked';
    const vcls = open ? 'open' : e.noListener ? 'nolistener' : 'closed';
    return `<div class="g-edge ${cls}">
      <span class="g-from">${esc(e.from)}</span>
      <span class="g-arrow">── ${esc(e.port)} ──▶</span>
      <span class="g-to">${esc(e.to)}</span>
      <span class="g-verdict ${vcls}">${verdict}${e.elapsedMs != null ? ` ${e.elapsedMs}ms` : ''}</span>
      ${e.decidedBy ? `<span class="g-policies">decided by ${esc((e.decidedBy || []).join(', '))}</span>` : ''}
    </div>`;
  }).join('');
}

/* ── chain ────────────────────────────────────────────────── */

async function loadChain() {
  const { body } = await api('/api/chain');
  const host = $('#chain');
  if (!body || body._missing) { host.innerHTML = '<p class="empty">no chain recorded — run it from Control</p>'; return; }

  const undet = new Set(body.undetectable || []);
  const hops = body.hops || [];
  if (!hops.length) { host.innerHTML = '<p class="empty">chain recorded no hops</p>'; return; }

  host.innerHTML = hops.map((h) => {
    const noRule = undet.has(h.attackId);
    const verdict = noRule ? 'no rule' : 'rule fires';
    const vcls = noRule ? 'none' : 'ok';
    return `<div class="hop">
      <span class="hop-id">${esc(h.id)}</span>
      <span class="hop-tech">${esc(h.attackId)}</span>
      <span class="hop-verdict ${vcls}">${verdict}</span>
      <span>
        <span class="hop-what">${esc(h.what)}</span>
        <span class="hop-detail">${esc(h.detail || '')}</span>
      </span>
    </div>`;
  }).join('') + `
    <p class="lede" style="margin-top:14px">
      Chain ${esc(body.chainRun)} &middot; ${body.hopsSucceeded} of
      ${(body.hopsSucceeded || 0) + (body.hopsFailed || 0)} hops succeeded.
      ${undet.size
        ? `<strong>${undet.size} hop has no rule at all</strong>, so the chain is not fully detected and the report does not claim it is.`
        : 'Every hop has a rule.'}
    </p>`;
}

/* ── stream ───────────────────────────────────────────────── */

async function loadStream() {
  const schema = $('#schema-filter').value;
  const limit = $('#limit-filter').value;
  const host = $('#stream');
  host.innerHTML = '<p class="empty">loading…</p>';
  const { body } = await api(`/api/telemetry?limit=${encodeURIComponent(limit)}${schema ? `&schema=${encodeURIComponent(schema)}` : ''}`);
  if (!body || !body.events) { host.innerHTML = '<p class="empty">no events</p>'; return; }

  if (!body.events.length) {
    host.innerHTML = '<p class="empty">no events match that filter</p>';
    return;
  }
  host.innerHTML = body.events.map((e) => `
    <div class="ev">
      <span class="ev-t">${esc((e.collectedAt || '').replace('T', ' ').slice(0, 19))}</span>
      <span class="ev-s">${esc(e.schema || '')}</span>
      <span class="ev-d">${summarise(e)}</span>
    </div>`).join('');
}

/* Returns HTML, and escapes every value it interpolates itself.
   The caller must NOT escape the result: doing both escapes the <b> tags too and
   the stream rendered literal markup, which is exactly the sort of thing that
   looks like a data problem and is a rendering one. Values come from telemetry
   and are untrusted, so the escaping belongs here, next to the interpolation --
   not at some outer layer that this function's author cannot see. */
function summarise(e) {
  switch (e.schema) {
    case 'runtime/container-exec/v1': {
      const t = e.target || {}; const i = e.identity || {};
      const cmd = (e.commandLine || '').slice(0, 90);
      return `<b>${esc(i.effectiveIdentity || '?')}</b> ${esc(e.subresource || '')} → ${esc(t.namespace)}/${esc(t.pod)} · ${esc(cmd)}`;
    }
    case 'runtime/token-request/v1':
      return `<b>${esc(e.namespace)}/${esc(e.serviceAccount)}</b> requester=${esc(e.requesterClass)} code=${esc(e.responseCode)}`;
    case 'runtime/pod-log-read/v1':
      return `<b>${esc((e.identity || {}).effectiveIdentity)}</b> read ${esc(e.namespace)}/${esc(e.pod)}`;
    case 'network/denial-counter/v1': {
      const s = e.subject || {}; const c = e.counter || {};
      return `<b>${esc(s.namespace)}/${esc(s.pod)}</b> +${esc(c.deltaDenied)} denied of +${esc(c.deltaTotal)} (${esc(e.baselineState)})`;
    }
    case 'network/observed-flow/v1': {
      const s = e.source || {};
      return `<b>${esc(s.name || '?')}</b> → ${esc(e.dest)}:${esc(e.destPort)} [${esc(e.scope)}/${esc(e.state)}]`;
    }
    case 'runtime/workload-identity/v1':
      return `<b>${esc(e.namespace)}/${esc(e.pod)}</b> as ${esc(e.serviceAccount)}`;
    default:
      return esc(JSON.stringify(e).slice(0, 120));
  }
}

$('#schema-filter').addEventListener('change', loadStream);
$('#limit-filter').addEventListener('change', loadStream);
$('#reload-stream').addEventListener('click', loadStream);

/* ── control ──────────────────────────────────────────────── */

async function loadActions() {
  const { body } = await api('/api/actions');
  const host = $('#actions');
  if (!body) { host.innerHTML = '<p class="empty">could not load actions</p>'; return; }

  host.innerHTML = Object.entries(body).map(([name, spec]) => `
    <button class="act" data-a="${esc(name)}" data-m="${spec.mutating ? '1' : '0'}">
      <span class="act-n">${esc(name)}</span>
      <span class="act-d">${esc(spec.about)}</span>
      ${spec.mutating ? '<span class="act-m">changes cluster state</span>' : ''}
    </button>`).join('');

  $$('#actions .act').forEach((btn) => btn.addEventListener('click', () => runAction(btn)));
}

async function runAction(btn) {
  const name = btn.dataset.a;
  const mutating = btn.dataset.m === '1';

  if (mutating) {
    // The server requires ?confirm=yes. A browser confirm() is the second half of
    // that: the flag is the control, and this is the human-facing part of it.
    const okToRun = window.confirm(
      `"${name}" changes cluster state.\n\n` +
      'For `chain` this creates a pod in the business zone and mints a ' +
      'cluster-admin token.\n\nRun it?'
    );
    if (!okToRun) return;
  }

  const url = `/api/action/${encodeURIComponent(name)}${mutating ? '?confirm=yes' : ''}`;
  btn.disabled = true;
  const { status, body } = await api(url, { method: 'POST' });
  btn.disabled = false;

  if (status === 202 && body?.job) {
    state.jobs.set(body.job.id, body.job);
    renderJobs();
    toast(`${name} started`);
    pollJobs();
  } else {
    toast(body?.error || `${name} refused (${status})`, true);
  }
}

function renderJobs() {
  const host = $('#jobs');
  if (!state.jobs.size) { host.innerHTML = '<p class="empty">no jobs yet</p>'; return; }
  host.innerHTML = Array.from(state.jobs.values())
    .sort((a, b) => b.elapsedSeconds - a.elapsedSeconds)
    .map((j) => `
      <div class="job">
        <div class="job-h">
          <span class="job-n">${esc(j.name)}</span>
          <span class="job-s ${esc(j.state)}">${esc(j.state)}</span>
          <span class="job-t">${esc(j.exitCode == null ? '' : `exit ${j.exitCode} · `)}${j.elapsedSeconds}s</span>
        </div>
        <pre class="job-o">${esc((j.output || []).join('\n') || '(no output yet)')}</pre>
      </div>`).join('');
}

async function pollJobs() {
  if (state.pollTimer) return;
  const tick = async () => {
    let running = false;
    for (const [id, job] of state.jobs) {
      if (job.state === 'running') {
        const { body } = await api(`/api/job/${id}`);
        if (body?.job) {
          state.jobs.set(id, body.job);
          if (body.job.state === 'running') running = true;
        }
      }
    }
    renderJobs();
    if (!running) {
      state.pollTimer = null;
      // Results changed on disk, so the read views are now stale.
      loadHealth(); loadOverview(); loadGraph(); loadChain();
      toast('jobs finished — views refreshed');
      return;
    }
    state.pollTimer = setTimeout(tick, 1500);
  };
  state.pollTimer = setTimeout(tick, 800);
}

/* ── boot ─────────────────────────────────────────────────── */

loadHealth();
loadOverview();
setInterval(loadHealth, 15000);
