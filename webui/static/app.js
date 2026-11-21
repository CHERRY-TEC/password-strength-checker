/* Password Strength Checker - web UI controller.
   Vanilla JavaScript, no dependencies. Talks only to the local JSON API. */

'use strict';

const $ = (id) => document.getElementById(id);

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]));

function readCookie(name) {
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return '';
}

function authHeaders() {
  const headers = {};
  const csrf = readCookie('psc_csrf');
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const token = sessionStorage.getItem('psc_token');
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

async function api(path, options = {}) {
  const headers = { ...authHeaders(), ...(options.headers || {}) };
  const response = await fetch(path, { cache: 'no-store', ...options, headers });

  if (response.status === 401 && !options._retried) {
    const token = window.prompt('Enter the API token shown in the server console:');
    if (token) {
      sessionStorage.setItem('psc_token', token);
      return api(path, { ...options, _retried: true });
    }
  }

  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('json')
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    throw new Error(payload && payload.error ? payload.error : `Request failed (${response.status})`);
  }
  return payload;
}

function post(path, body) {
  return api(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
}

/* ------------------------------ notifications ---------------------------- */
let toastTimer;
function toast(message, kind = 'success') {
  const element = $('toast');
  element.textContent = message;
  element.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.className = 'toast'; }, 3600);
}

/* -------------------------------- navigation ----------------------------- */
function setTab(name) {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.tab === name);
  });
  document.querySelectorAll('.panel').forEach((panel) => {
    panel.classList.toggle('active', panel.id === `panel-${name}`);
  });
  if (name === 'records') loadRecords();
  if (name === 'analytics') loadSummary();
  if (name === 'tools') refreshState();
}

/* --------------------------------- helpers -------------------------------- */
function ratingColor(rating) {
  if (rating === 'Very Strong' || rating === 'Strong') return '#34d399';
  if (rating === 'Fair') return '#fbbf24';
  return '#fb7185';
}

function scoreClass(score) {
  if (score >= 80) return 'green';
  if (score >= 40) return 'amber';
  return 'red';
}

function ratingPillClass(rating) {
  if (rating === 'Very Strong' || rating === 'Strong') return 'green';
  if (rating === 'Fair') return 'amber';
  return 'red';
}

function yesNo(value) {
  return value
    ? '<span class="fact-value good">Yes</span>'
    : '<span class="fact-value bad">No</span>';
}

function verdict(rating) {
  const copy = {
    'Very Strong': 'Excellent. This password would resist practical offline attacks.',
    'Strong': 'Solid. Keep it unique to this account.',
    'Fair': 'Acceptable, but a few changes would improve it.',
    'Weak': 'Risky. Attackers could guess this in a short time.',
    'Very Weak': 'Critical. This password offers almost no protection.',
  };
  return copy[rating] || 'Analysis complete.';
}

/* --------------------------------- check ---------------------------------- */
let currentAnalysis = null;
let previewTimer = null;

function setBusy(busy, persist = false) {
  $('previewBtn').disabled = busy;
  $('saveBtn').disabled = busy || !$('passwordInput').value;
  const original = persist ? 'Saving…' : 'Analysing…';
  if (busy) {
    $('previewBtn').dataset.label = $('previewBtn').textContent;
    $('saveBtn').dataset.label = $('saveBtn').textContent;
    $('previewBtn').textContent = original;
    $('saveBtn').textContent = original;
  } else {
    $('previewBtn').textContent = $('previewBtn').dataset.label || 'Analyse only';
    $('saveBtn').textContent = $('saveBtn').dataset.label || 'Save check';
  }
}

function resetMeter() {
  $('meterFill').style.width = '0%';
  $('meterLabel').textContent = 'Waiting for input';
  $('meterScore').textContent = '—';
}

function schedulePreview() {
  $('saveBtn').disabled = !$('passwordInput').value;
  clearTimeout(previewTimer);
  if (!$('passwordInput').value) {
    resetMeter();
    return;
  }
  previewTimer = setTimeout(() => runAnalyze(false), 200);
}

async function runAnalyze(persist) {
  const password = $('passwordInput').value;
  if (!password) {
    toast('Enter a password first.', 'warning');
    return;
  }
  const label = $('labelInput').value.trim();
  if (persist && !label) {
    toast('Add a label before saving the check.', 'warning');
    $('labelInput').focus();
    return;
  }

  setBusy(true, persist);
  try {
    const data = await post('/api/analyze', { password, label, persist });
    currentAnalysis = data.analysis;
    renderMeter(data.analysis);
    renderResult(data.analysis, data.flag, data.record);
    if (data.drift) renderDrift(data.drift);

    if (persist) {
      toast(`Check saved as record #${data.record.id}.`, 'success');
      $('passwordInput').value = '';
      resetMeter();
      $('saveBtn').disabled = true;
      await refreshState();
    }
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

function renderDrift(drift) {
  const card = $('driftCard');
  if (!card) return;
  card.classList.remove('hidden');
  const nearest = drift.nearest_id === null ? 'baseline' : `#${drift.nearest_id}`;
  $('driftText').innerHTML =
    `<div class="drift-line">Adaptive personal risk: <span class="drift-metric">${drift.personal_risk}/100</span> · ` +
    `nearest structure: <span class="drift-metric">${escapeHtml(String(nearest))}</span> · ` +
    `similarity: <span class="drift-metric">${Math.round(drift.similarity * 100)}%</span> · ` +
    `portfolio diversity: <span class="drift-metric">${Math.round(drift.diversity * 100)}%</span></div>` +
    `<div class="drift-line">${escapeHtml(drift.advice)}</div>`;
}

function renderMeter(analysis) {
  const colour = ratingColor(analysis.rating);
  $('meterFill').style.width = `${analysis.score}%`;
  $('meterFill').style.background = colour;
  $('meterLabel').textContent = analysis.rating;
  $('meterLabel').style.color = colour;
  $('meterScore').textContent = `${analysis.score}/100`;
}

function renderResult(analysis, flagged, record) {
  $('emptyState').classList.add('hidden');
  $('resultBody').classList.remove('hidden');
  $('resultTag').textContent = record ? `Saved #${record.id}` : 'Live preview';

  const colour = ratingColor(analysis.rating);
  const circumference = 2 * Math.PI * 52;
  const offset = circumference * (1 - analysis.score / 100);
  $('ringWrap').innerHTML = `
    <svg class="ring" viewBox="0 0 120 120" aria-hidden="true">
      <circle class="ring-bg" cx="60" cy="60" r="52"></circle>
      <circle class="ring-fg" cx="60" cy="60" r="52"
        style="stroke:${colour};stroke-dasharray:${circumference.toFixed(1)};stroke-dashoffset:${offset.toFixed(1)}"></circle>
    </svg>
    <div class="ring-center">
      <span class="ring-score" style="color:${colour}">${analysis.score}</span>
      <span class="ring-label">/ 100</span>
    </div>`;

  const badge = $('ratingBadge');
  badge.textContent = analysis.rating;
  badge.style.color = colour;
  badge.style.borderColor = colour + '66';
  badge.style.background = colour + '1f';
  $('verdictText').textContent = verdict(analysis.rating);
  $('weakFlag').classList.toggle('hidden', !flagged);

  const facts = [
    ['Length', `${analysis.length} chars`, ''],
    ['Character classes', `${analysis.char_classes} / 4`, analysis.char_classes >= 3 ? 'good' : 'bad'],
    ['Uppercase', yesNo(analysis.has_upper), ''],
    ['Lowercase', yesNo(analysis.has_lower), ''],
    ['Digits', yesNo(analysis.has_digit), ''],
    ['Symbols', yesNo(analysis.has_special), ''],
    ['Entropy', `${analysis.entropy_bits} bits`, ''],
    ['Crack time', analysis.crack_time, ''],
  ];
  $('factsGrid').innerHTML = facts.map(([label, value, klass]) => `
    <div class="fact">
      <div class="fact-label">${escapeHtml(label)}</div>
      <div class="fact-value ${klass}">${value}</div>
    </div>`).join('');

  $('issuesList').innerHTML = analysis.issues.length
    ? analysis.issues.map((issue) => `<li>${escapeHtml(issue)}</li>`).join('')
    : '<li class="none">No issues detected.</li>';
  $('suggestionsList').innerHTML = analysis.suggestions.length
    ? analysis.suggestions.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
    : '<li class="none">Nothing to add.</li>';
}

/* -------------------------------- records --------------------------------- */
let allRecords = [];
let filteredRecords = [];
let currentPage = 1;
const pageSize = 10;

async function loadRecords() {
  try {
    const params = new URLSearchParams();
    const query = $('searchInput').value.trim();
    const rating = $('ratingFilter').value;
    const minimum = $('minScore').value;
    if (query) params.set('q', query);
    if (rating) params.set('rating', rating);
    if (minimum !== '') params.set('min_score', minimum);

    const data = await api(`/api/records?${params.toString()}`);
    allRecords = data.records;
    filteredRecords = data.records;
    currentPage = 1;
    renderRecords();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function renderRecords() {
  const pages = Math.max(1, Math.ceil(filteredRecords.length / pageSize));
  currentPage = Math.min(currentPage, pages);
  const slice = filteredRecords.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  $('recordsBody').innerHTML = slice.length
    ? slice.map((record) => {
        const analysis = record.analysis;
        const checked = record.checked_at.replace('T', ' ').slice(0, 16);
        return `
          <tr data-id="${record.id}">
            <td class="mono">#${record.id}</td>
            <td class="label-cell">${escapeHtml(record.label)}</td>
            <td class="mono">${escapeHtml(checked)}</td>
            <td><span class="score-mini ${scoreClass(analysis.score)}">${analysis.score}</span></td>
            <td><span class="pill ${ratingPillClass(analysis.rating)}">${escapeHtml(analysis.rating)}</span></td>
            <td class="mono">${analysis.length}</td>
            <td class="actions-cell"><button class="row-delete" data-id="${record.id}" title="Delete record" aria-label="Delete record">✕</button></td>
          </tr>`;
      }).join('')
    : '<tr class="empty-row"><td colspan="7">No records match these filters.</td></tr>';

  $('recordsInfo').textContent = `${filteredRecords.length} shown · ${allRecords.length} total`;
  $('pageInfo').textContent = `${currentPage} / ${pages}`;
  $('prevPage').disabled = currentPage === 1;
  $('nextPage').disabled = currentPage === pages;
}

async function deleteRecord(id) {
  if (!window.confirm(`Delete record #${id}? This cannot be undone.`)) return;
  try {
    const data = await api(`/api/records/${id}`, { method: 'DELETE' });
    toast(`Record #${id} deleted · ${data.total} remaining.`, 'success');
    await loadRecords();
    await loadSummary();
    await refreshState();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function openDetail(id) {
  const record = allRecords.find((item) => item.id === id);
  if (!record) return;
  const analysis = record.analysis;
  const facts = [
    ['Score', `${analysis.score} / 100`],
    ['Rating', analysis.rating],
    ['Length', `${analysis.length} chars`],
    ['Entropy', `${analysis.entropy_bits} bits`],
    ['Crack time', analysis.crack_time],
    ['Checked', record.checked_at.replace('T', ' ').slice(0, 19)],
  ];
  $('detailTitle').textContent = `Record #${record.id} · ${record.label}`;
  $('detailContent').innerHTML = `
    <div class="facts">${facts.map(([label, value]) => `
      <div class="fact"><div class="fact-label">${escapeHtml(label)}</div>
      <div class="fact-value">${escapeHtml(value)}</div></div>`).join('')}</div>
    <h3 class="mini-head">Issues</h3>
    <ul class="list issues">${analysis.issues.length
      ? analysis.issues.map((issue) => `<li>${escapeHtml(issue)}</li>`).join('')
      : '<li class="none">None</li>'}</ul>
    <h3 class="mini-head" style="margin-top:16px">Suggestions</h3>
    <ul class="list suggestions">${analysis.suggestions.length
      ? analysis.suggestions.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
      : '<li class="none">None</li>'}</ul>`;
  $('detailModal').classList.remove('hidden');
}

function closeDetail() {
  $('detailModal').classList.add('hidden');
}

/* -------------------------------- analytics ------------------------------ */
async function loadSummary() {
  try {
    const data = await api('/api/summary');
    renderSummary(data.summary);
  } catch (error) {
    toast(error.message, 'error');
  }
}

function renderSummary(summary) {
  const cards = [
    ['Total records', summary.total, `${summary.strong_count} strong · ${summary.weak_count} weak`],
    ['Average score', summary.total ? summary.average_score : '—',
      summary.total ? `median ${summary.median_score} · range ${summary.min_score}–${summary.max_score}` : 'no data'],
    ['Average length', summary.total ? summary.average_length : '—', 'characters'],
    ['Weak share', summary.total ? `${Math.round(summary.weak_rate * 100)}%` : '—',
      `${summary.weak_count} of ${summary.total} records`],
    ['Structural diversity', summary.total ? `${Math.round((summary.structural_diversity || 0) * 100)}%` : '—',
      'portfolio variety (SDI)'],
  ];
  $('metricCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="metric">
      <div class="metric-label">${escapeHtml(label)}</div>
      <div class="metric-value">${escapeHtml(value)}</div>
      <div class="metric-sub">${escapeHtml(sub)}</div>
    </div>`).join('');

  const ratingClasses = {
    'Very Strong': 'vs', 'Strong': 'st', 'Fair': 'fa', 'Weak': 'we', 'Very Weak': 'vw',
  };
  renderBars($('ratingBars'), summary.rating_distribution, 'name', 'count',
    (item) => ratingClasses[item.name] || '');
  renderBars($('coverageBars'),
    Object.entries(summary.class_coverage).map(([name, count]) => ({ name, count })),
    'name', 'count');
  renderBars($('issueBars'),
    summary.common_issues.map((item) => ({ name: item.issue, count: item.count })),
    'name', 'count');

  $('activityBars').innerHTML = summary.per_day.length
    ? summary.per_day.map((item) => `
        <div class="bar-row">
          <span class="bar-label" title="${escapeHtml(item.day)}">${escapeHtml(item.day)}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${Math.round(item.count / summary.total * 100)}%"></span></span>
          <span class="bar-value">${item.count}</span>
        </div>`).join('')
    : '<p class="muted">No activity recorded yet.</p>';

  $('alerts').innerHTML = summary.alerts.map((alert) => `
    <div class="alert ${escapeHtml(alert.level)}">
      <span class="alert-tag">${escapeHtml(alert.level)}</span>
      <span>${escapeHtml(alert.message)}</span>
    </div>`).join('');

  $('extremes').innerHTML = `
    <div class="extreme">
      <div class="extreme-label">Strongest record</div>
      <div class="extreme-name">${summary.strongest
        ? `${escapeHtml(summary.strongest.label)} · ${summary.strongest.analysis.score}/100`
        : 'No data'}</div>
    </div>
    <div class="extreme">
      <div class="extreme-label">Weakest record</div>
      <div class="extreme-name">${summary.weakest
        ? `${escapeHtml(summary.weakest.label)} · ${summary.weakest.analysis.score}/100`
        : 'No data'}</div>
    </div>`;
}

function renderBars(container, items, labelKey, valueKey, classFn) {
  if (!items.length) {
    container.innerHTML = '<p class="muted">No data yet.</p>';
    return;
  }
  const maximum = Math.max(1, ...items.map((item) => item[valueKey]));
  container.innerHTML = items.map((item) => `
    <div class="bar-row ${classFn ? classFn(item) : ''}">
      <span class="bar-label" title="${escapeHtml(item[labelKey])}">${escapeHtml(item[labelKey])}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${Math.round(item[valueKey] / maximum * 100)}%"></span></span>
      <span class="bar-value">${item[valueKey]}</span>
    </div>`).join('');
}

/* ---------------------------------- tools --------------------------------- */
async function refreshState() {
  try {
    const state = await api('/api/state');
    $('storageChip').textContent = state.format.toUpperCase();
    $('storageDescription').textContent =
      `Backend: ${state.format.toUpperCase()} · ${state.total} record(s) · ${state.json_path}`;
    document.querySelectorAll('#formatSwitch button').forEach((button) => {
      button.classList.toggle('active', button.dataset.format === state.format);
    });
    if (state.warnings.length) toast(state.warnings[0], 'warning');
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function loadRules() {
  try {
    const data = await api('/api/rules');
    $('rulesList').innerHTML = data.rules.map((rule, index) => `
      <div class="rule">
        <div class="rule-title">${index + 1}. ${escapeHtml(rule.title)}</div>
        <p><strong>Rule:</strong> ${escapeHtml(rule.rule)}</p>
        <p><strong>Why:</strong> ${escapeHtml(rule.why)}</p>
      </div>`).join('');
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function seedData() {
  const count = Number($('seedCount').value);
  const replace = $('seedReplace').checked;
  try {
    const data = await post('/api/seed', { count, replace });
    toast(`Added ${data.added} sample records · ${data.total} total.`, 'success');
    await refreshState();
    await loadSummary();
    await loadRecords();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function importCsv() {
  const path = $('importPath').value.trim();
  try {
    const data = await post('/api/import', { path });
    const skipped = data.messages.filter((message) => message.startsWith('Skipped')).length;
    toast(`Imported ${data.imported} row(s), skipped ${skipped} · ${data.total} total.`,
      skipped ? 'warning' : 'success');
    await refreshState();
    await loadSummary();
    await loadRecords();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function switchFormat(format) {
  try {
    const data = await post('/api/format', { format });
    toast(`${format.toUpperCase()} active · ${data.total} record(s). ${data.messages[0] || ''}`.trim(), 'success');
    await refreshState();
    await loadRecords();
    await loadSummary();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function reloadFromDisk() {
  try {
    const data = await post('/api/reload', {});
    toast(`Reloaded ${data.total} record(s).`, 'success');
    await refreshState();
    await loadRecords();
    await loadSummary();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function exportReport(kind) {
  try {
    const response = await fetch(`/api/export?kind=${kind}`, { cache: 'no-store' });
    const contentType = response.headers.get('content-type') || '';
    if (!response.ok) {
      if (contentType.includes('json')) {
        const data = await response.json();
        throw new Error(data.error || 'Export failed');
      }
      throw new Error('Export failed');
    }
    const blob = await response.blob();
    const filename = response.headers.get('X-Filename') || `password-report.${kind}`;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast(`${kind.toUpperCase()} report downloaded.`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
}

/* --------------------------------- wiring --------------------------------- */
function wireEvents() {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => setTab(tab.dataset.tab));
  });

  $('togglePassword').addEventListener('click', () => {
    const input = $('passwordInput');
    const wasHidden = input.type === 'password';
    input.type = wasHidden ? 'text' : 'password';
    $('togglePassword').setAttribute('aria-label', wasHidden ? 'Hide password' : 'Show password');
  });

  $('passwordInput').addEventListener('input', schedulePreview);
  $('labelInput').addEventListener('input', () => {
    $('saveBtn').disabled = !$('passwordInput').value;
  });
  $('previewBtn').addEventListener('click', () => runAnalyze(false));
  $('saveBtn').addEventListener('click', () => runAnalyze(true));

  let filterTimer;
  const debounceFilters = () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(loadRecords, 200);
  };
  $('searchInput').addEventListener('input', debounceFilters);
  $('minScore').addEventListener('input', debounceFilters);
  $('ratingFilter').addEventListener('change', loadRecords);
  $('clearFilters').addEventListener('click', () => {
    $('searchInput').value = '';
    $('ratingFilter').value = '';
    $('minScore').value = '';
    loadRecords();
  });
  $('prevPage').addEventListener('click', () => { currentPage -= 1; renderRecords(); });
  $('nextPage').addEventListener('click', () => { currentPage += 1; renderRecords(); });

  $('recordsBody').addEventListener('click', (event) => {
    const remove = event.target.closest('.row-delete');
    if (remove) {
      event.stopPropagation();
      deleteRecord(Number(remove.dataset.id));
      return;
    }
    const row = event.target.closest('tr[data-id]');
    if (row) openDetail(Number(row.dataset.id));
  });

  $('closeModal').addEventListener('click', closeDetail);
  $('detailModal').querySelector('.modal-backdrop').addEventListener('click', closeDetail);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDetail();
  });

  $('seedBtn').addEventListener('click', seedData);
  $('importBtn').addEventListener('click', importCsv);
  $('reloadBtn').addEventListener('click', reloadFromDisk);
  document.querySelectorAll('#formatSwitch button').forEach((button) => {
    button.addEventListener('click', () => switchFormat(button.dataset.format));
  });
  document.querySelectorAll('[data-export]').forEach((button) => {
    button.addEventListener('click', () => exportReport(button.dataset.export));
  });
}

document.addEventListener('DOMContentLoaded', () => {
  wireEvents();
  refreshState();
  loadRules();
});
