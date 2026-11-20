/* Password Strength Checker - static (browser-only) application controller.
 * No backend. Records live in localStorage and contain analysis metadata only.
 */

'use strict';

const $ = (id) => document.getElementById(id);
const STORAGE_KEY = 'psc.records.v1';
const NEXT_ID_KEY = 'psc.nextId.v1';
const WEAK_THRESHOLD = 40;
const CRITICAL_WEAK_RATE = 0.40;
const SHORT_LENGTH_WARNING = 10;
const PAGE_SIZE = 10;

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]));

/* ------------------------------ notifications ---------------------------- */
let toastTimer;
function toast(message, kind = 'success') {
  const element = $('toast');
  element.textContent = message;
  element.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { element.className = 'toast'; }, 3600);
}

/* -------------------------------- storage -------------------------------- */
let records = [];
let nextId = 1;

function loadRecordsFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    records = Array.isArray(parsed) ? parsed.filter(isValidRecord) : [];
  } catch (error) {
    records = [];
    toast('Stored records were unreadable; started with an empty set.', 'warning');
  }
  const saved = Number(localStorage.getItem(NEXT_ID_KEY));
  nextId = Number.isFinite(saved) && saved > 0
    ? saved
    : records.reduce((maximum, record) => Math.max(maximum, record.id), 0) + 1;
  renderStorageInfo();
}

function isValidRecord(record) {
  return record && Number.isFinite(record.id) && typeof record.label === 'string'
    && record.analysis && Number.isFinite(record.analysis.score);
}

function persistRecords() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
    localStorage.setItem(NEXT_ID_KEY, String(nextId));
    renderStorageInfo();
    return true;
  } catch (error) {
    toast('Could not save to browser storage: ' + error.message, 'error');
    return false;
  }
}

function renderStorageInfo() {
  const bytes = (localStorage.getItem(STORAGE_KEY) || '').length;
  $('storageDescription').textContent =
    `${records.length} record(s) · ${bytes.toLocaleString()} bytes in this browser's local storage · no passwords included`;
}

/* -------------------------------- nav/helpers ---------------------------- */
function setTab(name) {
  document.querySelectorAll('.tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
  document.querySelectorAll('.panel').forEach((panel) => panel.classList.toggle('active', panel.id === `panel-${name}`));
  if (name === 'records') renderRecords();
  if (name === 'analytics') renderSummary();
  if (name === 'tools') renderStorageInfo();
}

function ratingColor(rating) {
  if (rating === 'Very Strong' || rating === 'Strong') return '#34d399';
  if (rating === 'Fair') return '#fbbf24';
  return '#fb7185';
}
function scoreClass(score) { return score >= 80 ? 'green' : score >= 40 ? 'amber' : 'red'; }
function ratingPillClass(rating) {
  if (rating === 'Very Strong' || rating === 'Strong') return 'green';
  if (rating === 'Fair') return 'amber';
  return 'red';
}
function yesNo(value) {
  return value ? '<span class="fact-value good">Yes</span>' : '<span class="fact-value bad">No</span>';
}
function verdict(rating) {
  return {
    'Very Strong': 'Excellent. This password would resist practical offline attacks.',
    'Strong': 'Solid. Keep it unique to this account.',
    'Fair': 'Acceptable, but a few changes would improve it.',
    'Weak': 'Risky. Attackers could guess this in a short time.',
    'Very Weak': 'Critical. This password offers almost no protection.',
  }[rating] || 'Analysis complete.';
}

/* --------------------------------- check ---------------------------------- */
function resetMeter() {
  $('meterFill').style.width = '0%';
  $('meterLabel').textContent = 'Waiting for input';
  $('meterLabel').style.color = '';
  $('meterScore').textContent = '—';
}

function schedulePreview() {
  $('saveBtn').disabled = !$('passwordInput').value;
  const password = $('passwordInput').value;
  if (!password) { resetMeter(); return; }
  const analysis = Analyzer.analyzePassword(password);
  renderMeter(analysis);
  renderResult(analysis, analysis.score < WEAK_THRESHOLD, null);
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
    <div class="fact"><div class="fact-label">${escapeHtml(label)}</div>
    <div class="fact-value ${klass}">${value}</div></div>`).join('');

  $('issuesList').innerHTML = analysis.issues.length
    ? analysis.issues.map((issue) => `<li>${escapeHtml(issue)}</li>`).join('')
    : '<li class="none">No issues detected.</li>';
  $('suggestionsList').innerHTML = analysis.suggestions.length
    ? analysis.suggestions.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
    : '<li class="none">Nothing to add.</li>';
}

function saveCheck() {
  const password = $('passwordInput').value;
  const label = $('labelInput').value.trim().replace(/[\x00-\x1f\x7f]/g, '').slice(0, 60);
  if (!password) { toast('Enter a password first.', 'warning'); return; }
  if (!label) { toast('Add a label before saving the check.', 'warning'); $('labelInput').focus(); return; }

  const analysis = Analyzer.analyzePassword(password);
  const record = {
    id: nextId++,
    label: label,
    checked_at: new Date().toISOString().replace(/\.\d{3}Z$/, ''),
    analysis: analysis,
  };
  records.push(record);
  if (persistRecords()) {
    toast(`Check saved as record #${record.id}.`, 'success');
    renderResult(analysis, analysis.score < WEAK_THRESHOLD, record);
    $('passwordInput').value = '';
    $('saveBtn').disabled = true;
    resetMeter();
  } else {
    nextId -= 1;
    records.pop();
  }
}

/* -------------------------------- records --------------------------------- */
let filtered = [];
let currentPage = 1;

function recordMatches(record, tokens) {
  const haystack = [record.label, record.analysis.rating, record.checked_at,
    ...record.analysis.issues, ...record.analysis.suggestions].join(' ').toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}

function renderRecords() {
  const query = $('searchInput').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const rating = $('ratingFilter').value;
  const minimum = $('minScore').value === '' ? null : Number($('minScore').value);
  filtered = records.filter((record) =>
    (!query.length || recordMatches(record, query)) &&
    (!rating || record.analysis.rating === rating) &&
    (minimum === null || record.analysis.score >= minimum)
  ).sort((a, b) => b.id - a.id);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  currentPage = Math.min(currentPage, pages);
  const slice = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  $('recordsBody').innerHTML = slice.length
    ? slice.map((record) => {
        const a = record.analysis;
        const checked = record.checked_at.replace('T', ' ').slice(0, 16);
        return `<tr data-id="${record.id}">
          <td class="mono">#${record.id}</td>
          <td class="label-cell">${escapeHtml(record.label)}</td>
          <td class="mono">${escapeHtml(checked)}</td>
          <td><span class="score-mini ${scoreClass(a.score)}">${a.score}</span></td>
          <td><span class="pill ${ratingPillClass(a.rating)}">${escapeHtml(a.rating)}</span></td>
          <td class="mono">${a.length}</td>
          <td class="actions-cell"><button class="row-delete" data-id="${record.id}" title="Delete record" aria-label="Delete record">✕</button></td>
        </tr>`;
      }).join('')
    : '<tr class="empty-row"><td colspan="7">No records match these filters.</td></tr>';

  $('recordsInfo').textContent = `${filtered.length} shown · ${records.length} total`;
  $('pageInfo').textContent = `${currentPage} / ${pages}`;
  $('prevPage').disabled = currentPage === 1;
  $('nextPage').disabled = currentPage === pages;
}

function deleteRecord(id) {
  if (!confirm(`Delete record #${id}? This cannot be undone.`)) return;
  const before = records.length;
  records = records.filter((record) => record.id !== id);
  if (records.length === before) return;
  persistRecords();
  renderRecords();
  renderSummary();
  toast(`Record #${id} deleted.`, 'success');
}

function openDetail(id) {
  const record = records.find((item) => item.id === id);
  if (!record) return;
  const a = record.analysis;
  const facts = [
    ['Score', `${a.score} / 100`], ['Rating', a.rating], ['Length', `${a.length} chars`],
    ['Entropy', `${a.entropy_bits} bits`], ['Crack time', a.crack_time],
    ['Checked', record.checked_at.replace('T', ' ').slice(0, 19)],
  ];
  $('detailTitle').textContent = `Record #${record.id} · ${record.label}`;
  $('detailContent').innerHTML = `
    <div class="facts">${facts.map(([label, value]) => `
      <div class="fact"><div class="fact-label">${escapeHtml(label)}</div>
      <div class="fact-value">${escapeHtml(value)}</div></div>`).join('')}</div>
    <h3 class="mini-head">Issues</h3>
    <ul class="list issues">${a.issues.length ? a.issues.map((issue) => `<li>${escapeHtml(issue)}</li>`).join('') : '<li class="none">None</li>'}</ul>
    <h3 class="mini-head" style="margin-top:16px">Suggestions</h3>
    <ul class="list suggestions">${a.suggestions.length ? a.suggestions.map((item) => `<li>${escapeHtml(item)}</li>`).join('') : '<li class="none">None</li>'}</ul>`;
  $('detailModal').classList.remove('hidden');
}

/* -------------------------------- analytics ------------------------------ */
function buildSummary() {
  const total = records.length;
  const summary = {
    total, average_score: 0, median_score: 0, min_score: null, max_score: null,
    average_length: 0, weak_count: 0, strong_count: 0, weak_rate: 0, strong_rate: 0,
    rating_counts: {}, class_counts: {}, issue_counts: {}, per_day: {},
    strongest: null, weakest: null, alerts: [],
  };
  if (!total) {
    summary.alerts = [{ level: 'info', message: 'No records yet — check a password or seed sample data.' }];
    return summary;
  }
  const scores = records.map((record) => record.analysis.score).sort((a, b) => a - b);
  const lengths = records.map((record) => record.analysis.length);
  const mid = Math.floor(scores.length / 2);
  summary.average_score = Math.round((scores.reduce((a, b) => a + b, 0) / total) * 10) / 10;
  summary.median_score = scores.length % 2 ? scores[mid] : (scores[mid - 1] + scores[mid]) / 2;
  summary.min_score = scores[0];
  summary.max_score = scores[scores.length - 1];
  summary.average_length = Math.round((lengths.reduce((a, b) => a + b, 0) / total) * 10) / 10;

  for (const record of records) {
    const a = record.analysis;
    summary.rating_counts[a.rating] = (summary.rating_counts[a.rating] || 0) + 1;
    summary.per_day[record.checked_at.slice(0, 10)] = (summary.per_day[record.checked_at.slice(0, 10)] || 0) + 1;
    if (a.score < WEAK_THRESHOLD) summary.weak_count++;
    if (a.score >= 80) summary.strong_count++;
    for (const [name, present] of [['Uppercase', a.has_upper], ['Lowercase', a.has_lower], ['Digits', a.has_digit], ['Symbols', a.has_special]]) {
      if (present) summary.class_counts[name] = (summary.class_counts[name] || 0) + 1;
    }
    for (const issue of a.issues) summary.issue_counts[issue] = (summary.issue_counts[issue] || 0) + 1;
  }
  summary.weak_rate = summary.weak_count / total;
  summary.strong_rate = summary.strong_count / total;
  summary.strongest = records.reduce((best, r) => r.analysis.score > best.analysis.score ? r : best, records[0]);
  summary.weakest = records.reduce((worst, r) => r.analysis.score < worst.analysis.score ? r : worst, records[0]);

  if (summary.weak_rate > CRITICAL_WEAK_RATE) {
    summary.alerts.push({ level: 'critical', message: `${Math.round(summary.weak_rate * 100)}% of records are weak (${summary.weak_count}/${total}). Consider a password audit.` });
  } else if (summary.weak_count) {
    summary.alerts.push({ level: 'warning', message: `${summary.weak_count} weak record(s) detected in the dataset.` });
  }
  if (summary.average_length < SHORT_LENGTH_WARNING) {
    summary.alerts.push({ level: 'warning', message: `Average password length is only ${summary.average_length.toFixed(1)} characters (recommended: 12+).` });
  }
  if (summary.min_score < 20) {
    summary.alerts.push({ level: 'critical', message: `At least one record is in the 'Very Weak' band (score ${summary.min_score}).` });
  }
  if (summary.strong_rate >= 0.5) {
    summary.alerts.push({ level: 'info', message: `Good news: ${Math.round(summary.strong_rate * 100)}% of records are strong or very strong.` });
  }
  if (!summary.alerts.length) summary.alerts.push({ level: 'info', message: 'All thresholds look healthy. No anomalies detected.' });
  return summary;
}

function renderBars(container, items, labelKey, valueKey, classFn) {
  if (!items.length) { container.innerHTML = '<p class="muted">No data yet.</p>'; return; }
  const maximum = Math.max(1, ...items.map((item) => item[valueKey]));
  container.innerHTML = items.map((item) => `
    <div class="bar-row ${classFn ? classFn(item) : ''}">
      <span class="bar-label" title="${escapeHtml(item[labelKey])}">${escapeHtml(item[labelKey])}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${Math.round(item[valueKey] / maximum * 100)}%"></span></span>
      <span class="bar-value">${item[valueKey]}</span>
    </div>`).join('');
}

function renderSummary() {
  const summary = buildSummary();
  const cards = [
    ['Total records', summary.total, `${summary.strong_count} strong · ${summary.weak_count} weak`],
    ['Average score', summary.total ? summary.average_score : '—',
      summary.total ? `median ${summary.median_score} · range ${summary.min_score}–${summary.max_score}` : 'no data'],
    ['Average length', summary.total ? summary.average_length : '—', 'characters'],
    ['Weak share', summary.total ? `${Math.round(summary.weak_rate * 100)}%` : '—',
      `${summary.weak_count} of ${summary.total} records`],
  ];
  $('metricCards').innerHTML = cards.map(([label, value, sub]) => `
    <div class="metric"><div class="metric-label">${escapeHtml(label)}</div>
    <div class="metric-value">${escapeHtml(value)}</div>
    <div class="metric-sub">${escapeHtml(sub)}</div></div>`).join('');

  const ratingClasses = { 'Very Strong': 'vs', 'Strong': 'st', 'Fair': 'fa', 'Weak': 'we', 'Very Weak': 'vw' };
  renderBars($('ratingBars'),
    ['Very Strong', 'Strong', 'Fair', 'Weak', 'Very Weak'].map((name) => ({ name, count: summary.rating_counts[name] || 0 })),
    'name', 'count', (item) => ratingClasses[item.name]);
  renderBars($('coverageBars'),
    Object.entries(summary.class_counts).map(([name, count]) => ({ name, count })), 'name', 'count');
  renderBars($('issueBars'),
    Object.entries(summary.issue_counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([issue, count]) => ({ name: issue, count })),
    'name', 'count');

  const days = Object.entries(summary.per_day).sort((a, b) => b[0].localeCompare(a[0])).slice(0, 10);
  $('activityBars').innerHTML = days.length ? days.map(([day, count]) => `
    <div class="bar-row"><span class="bar-label" title="${escapeHtml(day)}">${escapeHtml(day)}</span>
    <span class="bar-track"><span class="bar-fill" style="width:${Math.round(count / summary.total * 100)}%"></span></span>
    <span class="bar-value">${count}</span></div>`).join('') : '<p class="muted">No activity recorded yet.</p>';

  $('alerts').innerHTML = summary.alerts.map((alert) => `
    <div class="alert ${escapeHtml(alert.level)}"><span class="alert-tag">${escapeHtml(alert.level)}</span>
    <span>${escapeHtml(alert.message)}</span></div>`).join('');

  $('extremes').innerHTML = `
    <div class="extreme"><div class="extreme-label">Strongest record</div>
      <div class="extreme-name">${summary.strongest ? `${escapeHtml(summary.strongest.label)} · ${summary.strongest.analysis.score}/100` : 'No data'}</div></div>
    <div class="extreme"><div class="extreme-label">Weakest record</div>
      <div class="extreme-name">${summary.weakest ? `${escapeHtml(summary.weakest.label)} · ${summary.weakest.analysis.score}/100` : 'No data'}</div></div>`;
}

/* ---------------------------------- tools --------------------------------- */
function renderRules() {
  $('rulesList').innerHTML = Analyzer.explainRules().map((rule, index) => `
    <div class="rule"><div class="rule-title">${index + 1}. ${escapeHtml(rule.title)}</div>
    <p><strong>Rule:</strong> ${escapeHtml(rule.rule)}</p>
    <p><strong>Why:</strong> ${escapeHtml(rule.why)}</p></div>`).join('');
}

function seedData() {
  const count = Math.max(1, Math.min(200, Number($('seedCount').value) || 40));
  const replace = $('seedReplace').checked;
  const generated = [];
  const startId = replace ? 1 : nextId;
  const now = Date.now();
  for (let index = 0; index < count; index++) {
    const [baseLabel, sample] = Analyzer.SAMPLE_DATA[index % Analyzer.SAMPLE_DATA.length];
    const cycle = Math.floor(index / Analyzer.SAMPLE_DATA.length);
    const label = cycle ? `${baseLabel} (${cycle + 1})` : baseLabel;
    const when = new Date(now - ((index * 7 + 3) % 120) * 86400000).toISOString().replace(/\.\d{3}Z$/, '');
    generated.push({ id: startId + index, label: label.slice(0, 60), checked_at: when, analysis: Analyzer.analyzePassword(sample) });
  }
  records = replace ? generated : records.concat(generated);
  nextId = records.reduce((maximum, record) => Math.max(maximum, record.id), 0) + 1;
  persistRecords();
  renderRecords();
  renderSummary();
  toast(`Added ${count} sample records · ${records.length} total.`, 'success');
}

function clearAll() {
  if (!confirm('Delete all saved records? This cannot be undone.')) return;
  records = [];
  nextId = 1;
  persistRecords();
  renderRecords();
  renderSummary();
  toast('All records cleared.', 'success');
}

function parseCSV(text) {
  const rows = []; let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false; }
      else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(field); field = ''; }
    else if (char === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (char !== '\r') field += char;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function boolValue(value) { return /^(1|true|yes|y|on)$/i.test(String(value).trim()); }
function intValue(value, fallback) { const n = parseInt(value, 10); return Number.isFinite(n) ? n : fallback; }
function floatValue(value, fallback) { const n = parseFloat(value); return Number.isFinite(n) ? n : fallback; }
function listValue(value) {
  const text = String(value || '').trim();
  if (!text) return [];
  try { const parsed = JSON.parse(text); return Array.isArray(parsed) ? parsed : []; }
  catch (error) { return text.split(';').map((item) => item.trim()).filter(Boolean); }
}

function importCsv() {
  const file = $('importFile').files[0];
  if (!file) { toast('Choose a CSV file first.', 'warning'); return; }
  const reader = new FileReader();
  reader.onload = () => {
    const rows = parseCSV(String(reader.result));
    if (rows.length < 2) { toast('The CSV file has no data rows.', 'warning'); return; }
    const header = rows[0].map((cell) => cell.trim());
    const required = ['id', 'label', 'checked_at', 'score', 'rating', 'length'];
    const missing = required.filter((name) => !header.includes(name));
    if (missing.length) { toast('CSV is missing columns: ' + missing.join(', '), 'error'); return; }

    let imported = 0, skipped = 0;
    for (let index = 1; index < rows.length; index++) {
      const cells = rows[index];
      if (!cells.some((cell) => String(cell).trim())) continue;
      const row = {};
      header.forEach((name, position) => { row[name] = cells[position] || ''; });
      const id = intValue(row.id, 0);
      const timestamp = String(row.checked_at || '').replace(' ', 'T');
      if (id < 1 || !timestamp || isNaN(new Date(timestamp).getTime())) { skipped++; continue; }
      const analysis = {
        score: Math.max(0, Math.min(100, intValue(row.score, 0))),
        rating: String(row.rating || 'Unknown'),
        length: Math.max(0, intValue(row.length, 0)),
        has_upper: boolValue(row.has_upper), has_lower: boolValue(row.has_lower),
        has_digit: boolValue(row.has_digit), has_special: boolValue(row.has_special),
        char_classes: Math.max(0, Math.min(4, intValue(row.char_classes, 0))),
        entropy_bits: floatValue(row.entropy_bits, 0),
        crack_time: String(row.crack_time || 'unknown'),
        issues: listValue(row.issues), suggestions: listValue(row.suggestions),
      };
      records.push({ id: nextId++, label: String(row.label || 'Untitled').slice(0, 60), checked_at: timestamp, analysis });
      imported++;
    }
    persistRecords();
    renderRecords();
    renderSummary();
    toast(`Imported ${imported} row(s), skipped ${skipped} · ${records.length} total.`, skipped ? 'warning' : 'success');
  };
  reader.onerror = () => toast('Could not read that file.', 'error');
  reader.readAsText(file);
}

/* --------------------------------- exports -------------------------------- */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename;
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function stamp() { return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-'); }
function csvCell(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

function exportMarkdown() {
  const summary = buildSummary();
  const lines = [
    '# Password Strength Checker - Audit Report', '',
    `- Generated: ${new Date().toISOString()}`, '- Tool version: 1.0.0',
    `- Total analysed records: ${summary.total}`,
    '- Security note: only analysis metadata is stored; passwords are never saved.', '',
    '## Executive Summary', '', '| Metric | Value |', '| --- | --- |',
    `| Total records | ${summary.total} |`, `| Average score | ${summary.average_score}/100 |`,
    `| Median score | ${summary.median_score}/100 |`, `| Score range | ${summary.min_score} - ${summary.max_score} |`,
    `| Average length | ${summary.average_length} |`,
    `| Strong / very strong | ${summary.strong_count} (${Math.round(summary.strong_rate * 100)}%) |`,
    `| Weak / very weak | ${summary.weak_count} (${Math.round(summary.weak_rate * 100)}%) |`, '',
    '## Rating Distribution', '', '| Rating | Count |', '| --- | ---: |',
  ];
  for (const name of ['Very Strong', 'Strong', 'Fair', 'Weak', 'Very Weak']) {
    lines.push(`| ${name} | ${summary.rating_counts[name] || 0} |`);
  }
  lines.push('', '## Threshold Indicators', '');
  for (const alert of summary.alerts) lines.push(`- **${alert.level.toUpperCase()}**: ${alert.message}`);
  lines.push('', '## All Records', '', '| ID | Label | Checked at | Score | Rating | Length | Issues |',
    '| ---: | --- | --- | ---: | --- | ---: | --- |');
  for (const record of records) {
    const a = record.analysis;
    lines.push(`| ${record.id} | ${record.label.replace(/\|/g, '\\|')} | ${record.checked_at.replace('T', ' ').slice(0, 16)} | ${a.score} | ${a.rating} | ${a.length} | ${(a.issues.join('; ') || '-').replace(/\|/g, '\\|')} |`);
  }
  lines.push('', '---', '*Generated locally in your browser by Password Strength Checker v1.0.*', '');
  downloadBlob(new Blob([lines.join('\n')], { type: 'text/markdown' }), `summary-${stamp()}.md`);
}

function exportText() {
  const summary = buildSummary();
  const lines = ['='.repeat(72), 'PASSWORD STRENGTH CHECKER - PLAIN-TEXT AUDIT LOG',
    `Generated: ${new Date().toISOString()}`, '='.repeat(72),
    `Records: ${summary.total}`, `Average score: ${summary.average_score}/100`,
    `Average length: ${summary.average_length}`, `Weak records: ${summary.weak_count}`, '',
    'THRESHOLD INDICATORS', '-'.repeat(72)];
  for (const alert of summary.alerts) lines.push(`[${alert.level.toUpperCase().padEnd(8)}] ${alert.message}`);
  lines.push('', 'RECORD DETAIL', '-'.repeat(72));
  for (const record of records) {
    const a = record.analysis;
    lines.push(`#${String(record.id).padStart(4)} | ${record.label.padEnd(30).slice(0, 30)} | ${record.checked_at.slice(0, 19)} | score=${String(a.score).padStart(3)} | ${a.rating.padEnd(12)} | len=${String(a.length).padStart(3)}`);
    for (const issue of a.issues) lines.push(`         - issue: ${issue}`);
  }
  lines.push('', '='.repeat(72), `End of audit log (${records.length} records).`, '');
  downloadBlob(new Blob([lines.join('\n')], { type: 'text/plain' }), `audit-${stamp()}.txt`);
}

function exportCsv() {
  const fields = ['id', 'label', 'checked_at', 'score', 'rating', 'length', 'has_upper', 'has_lower',
    'has_digit', 'has_special', 'char_classes', 'entropy_bits', 'crack_time', 'issues', 'suggestions'];
  const rows = [fields.join(',')];
  for (const record of records) {
    const a = record.analysis;
    rows.push([
      record.id, record.label, record.checked_at, a.score, a.rating, a.length,
      a.has_upper, a.has_lower, a.has_digit, a.has_special, a.char_classes,
      a.entropy_bits, a.crack_time, JSON.stringify(a.issues), JSON.stringify(a.suggestions),
    ].map(csvCell).join(','));
  }
  downloadBlob(new Blob([rows.join('\r\n') + '\r\n'], { type: 'text/csv' }), `records-${stamp()}.csv`);
}

function exportPng() {
  if (!records.length) { toast('There are no records to chart yet.', 'warning'); return; }
  const summary = buildSummary();
  const names = ['Very Strong', 'Strong', 'Fair', 'Weak', 'Very Weak'];
  const counts = names.map((name) => summary.rating_counts[name] || 0);
  const colours = ['#2e7d32', '#66bb6a', '#f9a825', '#ef6c00', '#c62828'];
  const canvas = document.createElement('canvas');
  canvas.width = 900; canvas.height = 560;
  const context = canvas.getContext('2d');
  context.fillStyle = '#0e1424'; context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = '#eaf0ff'; context.font = 'bold 26px system-ui, sans-serif';
  context.fillText('Password Strength Checker - Rating Distribution', 50, 55);
  context.fillStyle = '#9aa8c8'; context.font = '15px system-ui, sans-serif';
  context.fillText(`Total records: ${summary.total}`, 50, 82);

  const maximum = Math.max(1, ...counts);
  const base = 470, width = 110, gap = 48;
  counts.forEach((count, index) => {
    const height = Math.round((count / maximum) * 320);
    const x = 85 + index * (width + gap);
    context.fillStyle = colours[index];
    context.fillRect(x, base - height, width, height);
    context.fillStyle = '#eaf0ff'; context.font = 'bold 18px ui-monospace, monospace';
    context.textAlign = 'center';
    context.fillText(String(count), x + width / 2, base - height - 12);
    context.fillStyle = '#9aa8c8'; context.font = '14px system-ui, sans-serif';
    context.fillText(names[index], x + width / 2, base + 26);
    context.textAlign = 'left';
  });
  context.strokeStyle = '#273353'; context.lineWidth = 2;
  context.beginPath(); context.moveTo(50, base); context.lineTo(850, base); context.stroke();
  canvas.toBlob((blob) => {
    if (blob) { downloadBlob(blob, `chart-${stamp()}.png`); toast('PNG chart downloaded.', 'success'); }
    else toast('Could not create the chart image.', 'error');
  }, 'image/png');
}

function exportReport(kind) {
  if (!records.length && kind !== 'png') { toast('There are no records to export yet.', 'warning'); return; }
  if (kind === 'md') exportMarkdown();
  else if (kind === 'txt') exportText();
  else if (kind === 'csv') exportCsv();
  else if (kind === 'png') exportPng();
}

/* --------------------------------- wiring --------------------------------- */
function wireEvents() {
  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => setTab(tab.dataset.tab)));

  $('togglePassword').addEventListener('click', () => {
    const input = $('passwordInput');
    const wasHidden = input.type === 'password';
    input.type = wasHidden ? 'text' : 'password';
    $('togglePassword').setAttribute('aria-label', wasHidden ? 'Hide password' : 'Show password');
  });
  $('passwordInput').addEventListener('input', schedulePreview);
  $('labelInput').addEventListener('input', () => { $('saveBtn').disabled = !$('passwordInput').value; });
  $('previewBtn').addEventListener('click', schedulePreview);
  $('saveBtn').addEventListener('click', saveCheck);

  const debounce = (fn) => { let timer; return () => { clearTimeout(timer); timer = setTimeout(fn, 150); }; };
  $('searchInput').addEventListener('input', debounce(renderRecords));
  $('minScore').addEventListener('input', debounce(renderRecords));
  $('ratingFilter').addEventListener('change', renderRecords);
  $('clearFilters').addEventListener('click', () => {
    $('searchInput').value = ''; $('ratingFilter').value = ''; $('minScore').value = '';
    renderRecords();
  });
  $('prevPage').addEventListener('click', () => { currentPage -= 1; renderRecords(); });
  $('nextPage').addEventListener('click', () => { currentPage += 1; renderRecords(); });

  $('recordsBody').addEventListener('click', (event) => {
    const remove = event.target.closest('.row-delete');
    if (remove) { event.stopPropagation(); deleteRecord(Number(remove.dataset.id)); return; }
    const row = event.target.closest('tr[data-id]');
    if (row) openDetail(Number(row.dataset.id));
  });
  $('closeModal').addEventListener('click', () => $('detailModal').classList.add('hidden'));
  $('detailModal').querySelector('.modal-backdrop').addEventListener('click', () => $('detailModal').classList.add('hidden'));
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') $('detailModal').classList.add('hidden'); });

  $('seedBtn').addEventListener('click', seedData);
  $('clearBtn').addEventListener('click', clearAll);
  $('importBtn').addEventListener('click', importCsv);
  document.querySelectorAll('[data-export]').forEach((button) => {
    button.addEventListener('click', () => exportReport(button.dataset.export));
  });
}

document.addEventListener('DOMContentLoaded', () => {
  wireEvents();
  loadRecordsFromStorage();
  renderRules();
  renderRecords();
  renderSummary();
});
