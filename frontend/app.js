// ============================================================
// AEGISWEB — MAIN DASHBOARD LOGIC (v1.2.1)
// Backend contract (backend/main.py):
//   POST /api/scan              -> ScanResult
//   GET  /api/history           -> list of scan history rows
//   GET  /api/history/{scan_id} -> ScanResult
// Subdomain recon lives in frontend/recon.js, loaded after this file.
// ============================================================

let currentScanData = null;
window.msfCommandMap = {};

let scoreGaugeChart = null;
let currentFindings = [];
let currentFindingFilter = 'ALL';
let toastTimer = null;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// R7-C3: only http(s) references may be rendered as clickable links.
function safeHttpUrl(url) {
  try {
    const u = new URL(String(url));
    return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : null;
  } catch (e) { return null; }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value === null || value === undefined ? '—' : String(value);
}

function getSeverityBadge(severity) {
  switch (String(severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-950 text-red-400 border border-red-800';
    case 'HIGH':
      return 'bg-orange-950 text-orange-400 border border-orange-800';
    case 'MEDIUM':
      return 'bg-yellow-950 text-yellow-400 border border-yellow-800';
    case 'LOW':
      return 'bg-blue-950 text-blue-400 border border-blue-800';
    default:
      return 'bg-slate-800 text-slate-300 border border-slate-700';
  }
}

function getSeverityBorder(severity) {
  switch (String(severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'border-red-800';
    case 'HIGH':
      return 'border-orange-800';
    case 'MEDIUM':
      return 'border-yellow-800';
    case 'LOW':
      return 'border-blue-800';
    default:
      return 'border-slate-700';
  }
}

function gradeBadgeClass(grade) {
  const classes = {
    A: 'bg-emerald-950 text-emerald-400 border border-emerald-800',
    B: 'bg-cyan-950 text-cyan-400 border border-cyan-800',
    C: 'bg-amber-950 text-amber-400 border border-amber-800',
    D: 'bg-orange-950 text-orange-400 border border-orange-800',
    F: 'bg-red-950 text-red-400 border border-red-800',
  };
  return classes[grade] || 'bg-cyber-700 text-slate-300 border border-cyber-600';
}

function showToast(message) {
  const toast = document.getElementById('toast');
  const text = document.getElementById('toast-message');
  if (!toast) return;

  if (text) text.textContent = message;
  toast.classList.remove('translate-y-20', 'opacity-0');
  toast.classList.add('translate-y-0', 'opacity-100');

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.add('translate-y-20', 'opacity-0');
    toast.classList.remove('translate-y-0', 'opacity-100');
  }, 2500);
}

function setSample(url) {
  const input = document.getElementById('target-url');
  if (!input) return;
  input.value = url;
  if (typeof autofillReconDomain === 'function') {
    autofillReconDomain(url);
  }
}

// ---------------------------------------------------------------------------
// Scan lifecycle
// ---------------------------------------------------------------------------
async function startScan() {
  const input = document.getElementById('target-url');
  const btnScan = document.getElementById('btn-scan');
  const progress = document.getElementById('scan-progress');
  const progressText = document.getElementById('progress-status-text');
  const progressBar = document.getElementById('progress-bar-fill');
  const results = document.getElementById('results-container');
  const errorBox = document.getElementById('scan-error');
  const errorMessage = document.getElementById('error-message');

  const url = input ? input.value.trim() : '';
  if (!url) {
    showToast('Vui lòng nhập URL mục tiêu cần quét!');
    if (input) input.focus();
    return;
  }

  const headersEl = document.getElementById('opt-headers');
  const sslEl = document.getElementById('opt-ssl');
  const reconEl = document.getElementById('opt-recon');

  const payload = {
    url: url,
    scan_headers: headersEl ? headersEl.checked : true,
    scan_ssl: sslEl ? sslEl.checked : true,
    scan_recon: reconEl ? reconEl.checked : true,
    timeout: 10,
  };

  if (btnScan) btnScan.disabled = true;
  if (results) results.classList.add('hidden');
  if (errorBox) errorBox.classList.add('hidden');
  if (progress) progress.classList.remove('hidden');
  if (progressBar) progressBar.style.width = '20%';
  if (progressText) progressText.textContent = 'Đang kết nối tới mục tiêu...';

  // Purely cosmetic progress hints; no additional network requests are made.
  const statusSteps = [
    'Đang kết nối tới mục tiêu...',
    'Đang phân tích Security Headers & SSL/TLS...',
    'Đang nhận diện công nghệ và tổng hợp điểm...',
  ];
  let stepIdx = 0;
  const statusTimer = setInterval(() => {
    stepIdx = Math.min(stepIdx + 1, statusSteps.length - 1);
    if (progressText) progressText.textContent = statusSteps[stepIdx];
    if (progressBar) progressBar.style.width = `${20 + stepIdx * 30}%`;
  }, 2500);

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    let data = null;
    try {
      data = await resp.json();
    } catch (parseErr) {
      data = null;
    }

    if (!resp.ok) {
      const detail = data && data.detail ? data.detail : `Máy chủ trả về HTTP ${resp.status}`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    if (!data) {
      throw new Error('Máy chủ trả về dữ liệu không hợp lệ.');
    }

    currentScanData = data;
    if (progressBar) progressBar.style.width = '100%';
    if (progressText) progressText.textContent = 'Hoàn tất phân tích.';
    renderResults(data);
    loadHistoryList();
  } catch (err) {
    if (errorMessage) {
      errorMessage.textContent = err && err.message ? err.message : 'Quét thất bại.';
    }
    if (errorBox) errorBox.classList.remove('hidden');
  } finally {
    clearInterval(statusTimer);
    if (progress) progress.classList.add('hidden');
    if (btnScan) btnScan.disabled = false;
  }
}

function renderResults(data) {
  if (!data) return;

  const summary = data.summary || {};
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const suggestions = Array.isArray(data.metasploit_suggestions) ? data.metasploit_suggestions : [];
  const technologies = Array.isArray(data.technologies) ? data.technologies : [];

  const countBySeverity = (sev) =>
    findings.filter((f) => String(f.severity || '').toUpperCase() === sev).length;

  const score = Number.isFinite(summary.score) ? summary.score : 0;
  const grade = summary.grade || '-';
  const critical = Number.isFinite(summary.critical) ? summary.critical : countBySeverity('CRITICAL');
  const high = Number.isFinite(summary.high) ? summary.high : countBySeverity('HIGH');
  const medium = Number.isFinite(summary.medium) ? summary.medium : countBySeverity('MEDIUM');
  const low = Number.isFinite(summary.low) ? summary.low : countBySeverity('LOW');

  setText('score-value', score);
  setText('gauge-center-text', `${score}%`);
  setText('count-critical', critical);
  setText('count-high', high);
  setText('count-medium', medium);
  setText('count-low', low);
  setText('meta-host', data.hostname);
  setText('meta-ip', data.ip_address);
  setText('meta-duration', Number.isFinite(data.duration_seconds) ? `${data.duration_seconds}s` : null);
  setText('badge-tab-findings', findings.length);
  setText('badge-tab-tech', technologies.length);

  const gradeEl = document.getElementById('grade-badge');
  if (gradeEl) {
    gradeEl.textContent = `Grade ${grade}`;
    gradeEl.className = `px-2.5 py-0.5 rounded text-xs font-bold ${gradeBadgeClass(grade)}`;
  }

  renderScoreGauge(score, grade);
  renderScanDiff(data.diff);

  currentFindings = findings;
  currentFindingFilter = 'ALL';
  syncFindingFilterButtons();
  renderFindingsList();

  renderHeaders(data.headers_analyzed);
  renderSslDetails(data.ssl_info);
  renderTechnologies(technologies);
  renderReconItems(data.recon_items);

  renderMetasploitSuggestions(suggestions);

  const resultsContainer = document.getElementById('results-container');
  if (resultsContainer) resultsContainer.classList.remove('hidden');

  if (window.lucide) lucide.createIcons();
}

function renderScoreGauge(score, grade) {
  const canvas = document.getElementById('scoreGaugeChart');
  if (!canvas || typeof Chart === 'undefined') return;

  if (scoreGaugeChart) {
    scoreGaugeChart.destroy();
    scoreGaugeChart = null;
  }

  const gaugeColors = {
    A: '#10b981',
    B: '#06b6d4',
    C: '#f59e0b',
    D: '#f97316',
    F: '#ef4444',
  };
  const color = gaugeColors[grade] || '#06b6d4';
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));

  scoreGaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Điểm an toàn', 'Còn lại'],
      datasets: [{
        data: [safeScore, Math.max(0, 100 - safeScore)],
        backgroundColor: [color, '#1f2937'],
        borderWidth: 0,
        hoverBackgroundColor: [color, '#1f2937'],
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '74%',
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
      },
    },
  });
}

function renderScanDiff(diff) {
  const banner = document.getElementById('scan-diff-banner');
  if (!banner) return;

  if (!diff || !diff.has_previous) {
    banner.classList.add('hidden');
    banner.innerHTML = '';
    return;
  }

  const delta = Number(diff.score_delta) || 0;
  const deltaText = delta > 0 ? `+${delta}` : String(delta);
  const deltaClass = delta > 0 ? 'text-emerald-400' : delta < 0 ? 'text-red-400' : 'text-slate-300';
  const newFindings = Array.isArray(diff.new_findings) ? diff.new_findings : [];
  const resolvedFindings = Array.isArray(diff.resolved_findings) ? diff.resolved_findings : [];
  const headersAdded = Array.isArray(diff.headers_added) ? diff.headers_added : [];
  const headersRemoved = Array.isArray(diff.headers_removed) ? diff.headers_removed : [];

  const renderTitles = (items) => {
    if (!items.length) return '<span class="text-slate-500">Không có</span>';
    const names = items.slice(0, 3).map((f) => escapeHtml(f.title || f.id || '')).join(', ');
    const suffix = items.length > 3 ? '...' : '';
    return `<span class="text-slate-300">${names}${suffix}</span>`;
  };

  banner.innerHTML = `
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyan-800/40 pb-3 mb-3">
      <div class="flex items-center gap-2 flex-wrap">
        <i data-lucide="history" class="w-4 h-4 text-cyan-400"></i>
        <strong class="text-white text-sm">Biến động so với lần quét trước</strong>
        <span class="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">${escapeHtml(diff.previous_scan_time || 'lần trước')}</span>
      </div>
      <span class="text-xs text-slate-400">Điểm lần trước: <span class="font-mono text-white">${escapeHtml(diff.previous_score)}</span></span>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
      <div class="bg-cyber-900/60 border border-cyber-700 rounded-lg p-3">
        <span class="text-slate-400 block mb-1">Điểm số</span>
        <span class="text-xl font-bold font-mono ${deltaClass}">${deltaText}</span>
      </div>
      <div class="bg-cyber-900/60 border border-cyber-700 rounded-lg p-3">
        <span class="text-slate-400 block mb-1">Lỗ hổng mới (${newFindings.length})</span>
        ${renderTitles(newFindings)}
      </div>
      <div class="bg-cyber-900/60 border border-cyber-700 rounded-lg p-3">
        <span class="text-slate-400 block mb-1">Đã khắc phục (${resolvedFindings.length})</span>
        ${renderTitles(resolvedFindings)}
      </div>
      <div class="bg-cyber-900/60 border border-cyber-700 rounded-lg p-3">
        <span class="text-slate-400 block mb-1">Security Headers</span>
        <span class="text-emerald-400">+${headersAdded.length}</span>
        <span class="text-slate-500">/</span>
        <span class="text-red-400">-${headersRemoved.length}</span>
      </div>
    </div>
  `;
  banner.classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
function renderFindingsList() {
  const container = document.getElementById('findings-list');
  if (!container) return;

  const list = currentFindingFilter === 'ALL'
    ? currentFindings
    : currentFindings.filter((f) => String(f.severity || '').toUpperCase() === currentFindingFilter);

  if (!list.length) {
    container.innerHTML = `
      <div class="text-center py-10 bg-cyber-800/40 rounded-xl border border-cyber-700">
        <i data-lucide="check-circle-2" class="w-10 h-10 text-emerald-500 mx-auto mb-2"></i>
        <p class="text-slate-400 text-sm">Không có lỗ hổng nào trong nhóm này.</p>
      </div>`;
    if (window.lucide) lucide.createIcons();
    return;
  }

  container.innerHTML = list.map((f) => {
    const severity = String(f.severity || 'INFO').toUpperCase();
    const badge = getSeverityBadge(severity);
    const border = getSeverityBorder(severity);
    const references = Array.isArray(f.references) ? f.references : [];

    return `
      <article data-severity="${escapeHtml(severity)}" class="bg-cyber-800 border ${border} rounded-xl p-5 space-y-3">
        <div class="flex items-start justify-between gap-3 flex-wrap">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="${badge} px-2.5 py-0.5 rounded-full text-xs font-bold uppercase">${escapeHtml(severity)}</span>
            <h3 class="font-bold text-white text-sm">${escapeHtml(f.title || '')}</h3>
          </div>
          <span class="text-[11px] px-2 py-0.5 rounded bg-cyber-700 text-slate-300 border border-cyber-600">${escapeHtml(f.category || '')}</span>
        </div>
        <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(f.description || '')}</p>
        ${f.evidence ? `<div class="bg-black/40 border border-cyber-700 rounded-lg p-2.5 font-mono text-[11px] text-amber-300 whitespace-pre-wrap break-all">${escapeHtml(f.evidence)}</div>` : ''}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div class="bg-red-950/20 border border-red-900/30 rounded-lg p-3">
            <strong class="text-red-400 block mb-1">Tác động:</strong>
            <span class="text-slate-300">${escapeHtml(f.impact || '')}</span>
          </div>
          <div class="bg-emerald-950/20 border border-emerald-900/30 rounded-lg p-3">
            <strong class="text-emerald-400 block mb-1">Khắc phục:</strong>
            <span class="text-slate-300">${escapeHtml(f.remediation || '')}</span>
          </div>
        </div>
        ${references.length ? `
          <div class="text-[11px] text-slate-400 flex flex-wrap gap-2 items-center">
            <span class="font-semibold text-slate-300">Tham khảo:</span>
            ${references.map((ref) => {
              const safe = safeHttpUrl(ref);
              return safe
                ? `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:text-cyan-300 underline break-all">${escapeHtml(ref)}</a>`
                : `<span class="break-all">${escapeHtml(ref)}</span>`;
            }).join('')}
          </div>` : ''}
        ${f.manual_check ? `
          <div class="bg-cyan-950/20 border border-cyan-900/40 rounded-lg p-3 text-xs">
            <strong class="text-cyan-400 block mb-1">How to verify manually:</strong>
            <span class="text-slate-300">${escapeHtml(f.manual_check)}</span>
          </div>` : ''}
      </article>`;
  }).join('');

  if (window.lucide) lucide.createIcons();
}

function syncFindingFilterButtons() {
  const buttons = document.querySelectorAll('.finding-filter-btn');
  const labelMap = {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
  };
  const colorMap = {
    CRITICAL: 'text-red-400',
    HIGH: 'text-orange-400',
    MEDIUM: 'text-yellow-400',
    LOW: 'text-blue-400',
  };

  buttons.forEach((btn) => {
    const label = (btn.textContent || '').trim().toUpperCase();
    const isAll = label === 'TẤT CẢ';
    const filterKey = isAll ? 'ALL' : labelMap[label] || null;
    const isActive = filterKey === currentFindingFilter;

    btn.classList.remove(
      'bg-cyber-700', 'text-white', 'font-medium',
      'bg-cyber-800', 'text-red-400', 'text-orange-400', 'text-yellow-400', 'text-blue-400'
    );

    if (isActive) {
      btn.classList.add('bg-cyber-700', 'text-white', 'font-medium');
    } else {
      btn.classList.add('bg-cyber-800');
      if (colorMap[filterKey]) btn.classList.add(colorMap[filterKey]);
    }
  });
}

function filterFindings(severity) {
  currentFindingFilter = severity || 'ALL';
  syncFindingFilterButtons();
  renderFindingsList();
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach((el) => el.classList.add('hidden'));

  const activeContent = document.getElementById(tabId);
  if (activeContent) activeContent.classList.remove('hidden');

  const activeBtnId = `btn-${tabId}`;
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    const isActive = btn.id === activeBtnId;
    btn.classList.remove(
      'border-b-2', 'border-purple-500', 'text-purple-400',
      'bg-cyber-800', 'text-slate-400'
    );
    if (isActive) {
      btn.classList.add('border-b-2', 'border-purple-500', 'text-purple-400', 'bg-cyber-800');
    } else {
      btn.classList.add('text-slate-400');
    }
  });

  if (window.lucide) lucide.createIcons();
}

// ---------------------------------------------------------------------------
// Headers / SSL / Technologies / Recon tables
// ---------------------------------------------------------------------------
function renderHeaders(headersAnalyzed) {
  const tbody = document.getElementById('headers-table-body');
  if (!tbody) return;

  const headers = headersAnalyzed && typeof headersAnalyzed === 'object' ? headersAnalyzed : {};
  // Only real header entries ({present, value}); skip e.g. "allowed_http_methods".
  const keys = Object.keys(headers).filter((key) => {
    const info = headers[key];
    return info !== null && typeof info === 'object' && !Array.isArray(info) && 'present' in info;
  });
  const allowedMethods = typeof headers.allowed_http_methods === 'string' ? headers.allowed_http_methods : null;

  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="px-6 py-6 text-center text-slate-500">Không có dữ liệu header.</td></tr>';
  } else {
    tbody.innerHTML = keys.map((key) => {
      const info = headers[key];
      const present = !!info.present;
      const value = info.value;

      const statusBadge = present
        ? '<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[11px] font-semibold"><i data-lucide="check" class="w-3 h-3"></i> Đã cấu hình</span>'
        : '<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-950 text-red-400 border border-red-800 text-[11px] font-semibold"><i data-lucide="x" class="w-3 h-3"></i> Thiếu</span>';
      const remediation = present ? 'Giữ nguyên cấu hình hiện tại' : 'Bổ sung theo khuyến nghị OWASP';

      return `
        <tr class="hover:bg-cyber-800/40">
          <td class="px-6 py-3 font-mono text-slate-200 break-all">${escapeHtml(key)}</td>
          <td class="px-6 py-3">${statusBadge}</td>
          <td class="px-6 py-3 font-mono text-[11px] text-amber-300 break-all">${present && value !== null && value !== undefined ? escapeHtml(value) : '<span class="text-slate-600">—</span>'}</td>
          <td class="px-6 py-3 text-slate-400">${escapeHtml(remediation)}</td>
        </tr>`;
    }).join('');
  }

  const table = tbody.closest('table');
  const wrapper = table ? table.parentElement : null;
  if (wrapper && wrapper.parentElement) {
    const existingNote = wrapper.parentElement.querySelector('.allowed-methods-note');
    if (existingNote) existingNote.remove();
    if (allowedMethods) {
      const note = document.createElement('div');
      note.className = 'allowed-methods-note px-6 py-3 border-t border-cyber-700 text-xs text-slate-400';
      note.innerHTML = `HTTP methods cho phép: <span class="font-mono text-cyan-300">${escapeHtml(allowedMethods)}</span>`;
      wrapper.insertAdjacentElement('afterend', note);
    }
  }

  if (window.lucide) lucide.createIcons();
}

function renderSslDetails(sslInfo) {
  const container = document.getElementById('ssl-details-container');
  if (!container) return;

  if (!sslInfo) {
    container.innerHTML = `
      <div class="text-center py-8">
        <i data-lucide="lock" class="w-10 h-10 text-slate-600 mx-auto mb-2"></i>
        <p class="text-slate-400 text-sm">Không có dữ liệu SSL/TLS cho mục tiêu này.</p>
      </div>`;
    if (window.lucide) lucide.createIcons();
    return;
  }

  const statusText = sslInfo.has_ssl
    ? (sslInfo.valid ? 'Hợp lệ' : 'Không hợp lệ')
    : 'Không có SSL/TLS';
  const statusClass = sslInfo.has_ssl && sslInfo.valid
    ? 'text-emerald-400 border-emerald-800 bg-emerald-950/40'
    : 'text-red-400 border-red-800 bg-red-950/40';

  const rows = [
    ['Nhà phát hành', sslInfo.issuer],
    ['Chủ thể', sslInfo.subject],
    ['Hết hạn sau', Number.isFinite(sslInfo.expires_in_days) ? `${sslInfo.expires_in_days} ngày` : null],
    ['Hiệu lực từ', sslInfo.not_before],
    ['Hiệu lực đến', sslInfo.not_after],
    ['Giao thức TLS', sslInfo.tls_version],
    ['Cipher', sslInfo.cipher],
    ['SAN', Array.isArray(sslInfo.san) && sslInfo.san.length ? sslInfo.san.join(', ') : null],
  ];

  const warnings = Array.isArray(sslInfo.warnings) ? sslInfo.warnings : [];

  container.innerHTML = `
    <div class="flex items-center justify-between gap-3 flex-wrap border-b border-cyber-700 pb-4">
      <div class="flex items-center gap-2">
        <span class="p-2 rounded-xl bg-cyber-900 border border-cyber-700 text-cyan-400"><i data-lucide="lock" class="w-5 h-5"></i></span>
        <div>
          <h3 class="font-semibold text-white text-sm">Chứng chỉ & Giao thức</h3>
          <p class="text-xs text-slate-400">Thẩm định SSL/TLS của máy chủ mục tiêu</p>
        </div>
      </div>
      <span class="px-3 py-1 rounded-full border text-xs font-bold ${statusClass}">${escapeHtml(statusText)}</span>
    </div>
    <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
      ${rows.map(([label, value]) => `
        <div class="bg-cyber-900/60 border border-cyber-700 rounded-lg p-3">
          <dt class="text-slate-500 mb-1">${escapeHtml(label)}</dt>
          <dd class="text-slate-200 font-mono break-all">${value !== null && value !== undefined && value !== '' ? escapeHtml(value) : '<span class="text-slate-600">—</span>'}</dd>
        </div>`).join('')}
    </dl>
    ${warnings.length ? `
      <div class="bg-amber-950/30 border border-amber-800/50 rounded-lg p-3 text-xs text-amber-300 space-y-1">
        <strong class="flex items-center gap-1"><i data-lucide="alert-triangle" class="w-3.5 h-3.5"></i> Cảnh báo (${warnings.length})</strong>
        <ul class="list-disc list-inside space-y-0.5">
          ${warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('')}
        </ul>
      </div>` : ''}
  `;

  if (window.lucide) lucide.createIcons();
}

function renderTechnologies(technologies) {
  const container = document.getElementById('tech-cards-container');
  if (!container) return;

  if (!technologies || !technologies.length) {
    container.innerHTML = `
      <div class="text-center py-8 bg-cyber-800/40 border border-cyber-700 rounded-xl col-span-full">
        <i data-lucide="cpu" class="w-10 h-10 text-slate-600 mx-auto mb-2"></i>
        <p class="text-slate-400 text-sm">Không nhận diện được công nghệ đặc thù.</p>
      </div>`;
    if (window.lucide) lucide.createIcons();
    return;
  }

  container.innerHTML = technologies.map((tech) => `
    <div class="bg-cyber-800 border border-cyber-700 hover:border-cyan-700/60 rounded-xl p-4 space-y-2 transition">
      <div class="flex items-center justify-between gap-2">
        <span class="font-semibold text-white text-sm break-all">${escapeHtml(tech.name || '')}</span>
        <span class="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800">${escapeHtml(tech.category || 'Technology')}</span>
      </div>
      <div class="flex items-center justify-between text-[11px] text-slate-400">
        <span>Phiên bản: <span class="font-mono text-slate-200">${escapeHtml(tech.version || '—')}</span></span>
        <span>Độ tin cậy: <span class="text-slate-200">${escapeHtml(tech.confidence || 'Medium')}</span></span>
      </div>
    </div>`).join('');

  if (window.lucide) lucide.createIcons();
}

function renderReconItems(reconItems) {
  const tbody = document.getElementById('recon-table-body');
  if (!tbody) return;

  if (!Array.isArray(reconItems) || !reconItems.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-6 text-center text-slate-500">Không có dữ liệu thăm dò endpoint.</td></tr>';
    return;
  }

  tbody.innerHTML = reconItems.map((item) => {
    const accessible = !!item.accessible;
    const statusCode = Number.isFinite(item.status_code) ? item.status_code : 0;
    const accessBadge = accessible
      ? '<span class="px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[11px] font-semibold">Có</span>'
      : '<span class="px-2 py-0.5 rounded-full bg-cyber-700 text-slate-300 border border-cyber-600 text-[11px] font-semibold">Không</span>';

    return `
      <tr class="hover:bg-cyber-800/40">
        <td class="px-6 py-3 text-slate-200">${escapeHtml(item.name || '')}</td>
        <td class="px-6 py-3 font-mono text-[11px] text-cyan-300 break-all">${escapeHtml(item.path || '')}</td>
        <td class="px-6 py-3 font-mono text-slate-300">${escapeHtml(statusCode)}</td>
        <td class="px-6 py-3">${accessBadge}</td>
        <td class="px-6 py-3 font-mono text-[11px] text-slate-400 max-w-xs break-all">${item.content_preview ? escapeHtml(item.content_preview) : '<span class="text-slate-600">—</span>'}</td>
      </tr>`;
  }).join('');
}

// ---------------------------------------------------------------------------
// Metasploit helpers
// ---------------------------------------------------------------------------
// R7-B1: badge/count reflect only the modules currently shown; hidden
// intrusive modules are noted separately.
function updateMsfBadges(suggestions) {
  const list = Array.isArray(suggestions) ? suggestions : [];
  const toggleCheckbox = document.getElementById('toggle-intrusive-msf');
  const showIntrusive = toggleCheckbox ? toggleCheckbox.checked : false;

  const normalCount = list.filter((s) => !s.intrusive).length;
  const intrusiveCount = list.filter((s) => !!s.intrusive).length;
  const visibleCount = showIntrusive ? normalCount + intrusiveCount : normalCount;

  setText('count-msf', visibleCount);
  setText('badge-tab-msf', visibleCount);

  const note = document.getElementById('count-msf-note');
  if (note) {
    const showNote = intrusiveCount > 0 && !showIntrusive;
    note.classList.toggle('hidden', !showNote);
    note.textContent = showNote ? `+${intrusiveCount} intrusive ẩn` : '';
  }
}

function copyMsfCommand(id) {
  const command = window.msfCommandMap ? window.msfCommandMap[id] : null;
  if (!command) {
    showToast('Không tìm thấy lệnh Metasploit để sao chép.');
    return;
  }

  const onSuccess = () => showToast('Đã sao chép lệnh kiểm thử!');
  const fallbackCopy = () => {
    try {
      const textarea = document.createElement('textarea');
      textarea.value = command;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.top = '-1000px';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(textarea);
      if (ok) onSuccess();
      else showToast('Không thể sao chép tự động.');
    } catch (err) {
      showToast('Không thể sao chép tự động.');
    }
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(command).then(onSuccess).catch(fallbackCopy);
  } else {
    fallbackCopy();
  }
}

function exportJSON() {
  if (!currentScanData) {
    showToast('Chưa có kết quả quét để xuất.');
    return;
  }

  try {
    const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `aegisweb-scan-${currentScanData.scan_id || Date.now()}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
    showToast('Đã xuất kết quả JSON.');
  } catch (err) {
    showToast('Xuất JSON thất bại.');
  }
}

// ---------------------------------------------------------------------------
// History drawer
// ---------------------------------------------------------------------------
async function loadHistoryList() {
  const container = document.getElementById('history-items-list');
  if (!container) return;

  container.innerHTML = '<div class="text-xs text-slate-500 text-center py-6">Đang tải lịch sử...</div>';

  try {
    const resp = await fetch('/api/history');
    if (!resp.ok) throw new Error(`Máy chủ trả về HTTP ${resp.status}`);

    const items = await resp.json();
    if (!Array.isArray(items) || !items.length) {
      container.innerHTML = '<div class="text-xs text-slate-500 text-center py-6">Chưa có lần quét nào.</div>';
      return;
    }

    container.innerHTML = '';

    items.forEach((item) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'w-full text-left bg-cyber-900/60 border border-cyber-700 hover:border-cyan-600 rounded-lg p-3 transition';
      button.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-xs text-white truncate">${escapeHtml(item.hostname || item.target_url || '')}</span>
          <span class="text-[10px] px-2 py-0.5 rounded-full font-bold whitespace-nowrap ${gradeBadgeClass(item.grade)}">${escapeHtml(item.grade || '-')}</span>
        </div>
        <div class="flex items-center justify-between gap-2 mt-1.5 text-[11px] text-slate-400">
          <span>${escapeHtml(item.scan_time || '')}</span>
          <span class="whitespace-nowrap">Điểm <span class="text-cyan-400 font-mono">${escapeHtml(item.score)}</span> • Lỗ hổng <span class="text-slate-200">${escapeHtml(item.total_findings)}</span></span>
        </div>
        <div class="mt-1 text-[10px] text-slate-500">${escapeHtml(item.status || '')}</div>`;
      button.addEventListener('click', () => openScanFromHistory(item.scan_id));
      container.appendChild(button);
    });
  } catch (err) {
    container.innerHTML = `<div class="text-xs text-red-400 text-center py-6">Không tải được lịch sử: ${escapeHtml(err.message)}</div>`;
  }
}

async function openScanFromHistory(scanId) {
  if (!scanId) return;

  try {
    const resp = await fetch(`/api/history/${encodeURIComponent(scanId)}`);
    const body = await resp.json().catch(() => null);

    if (!resp.ok) {
      const detail = body && body.detail ? body.detail : `Máy chủ trả về HTTP ${resp.status}`;
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    if (!body) throw new Error('Dữ liệu lịch sử không hợp lệ.');

    // R7-C1: clear any error left over from a previous failed scan.
    const errorBox = document.getElementById('scan-error');
    if (errorBox) errorBox.classList.add('hidden');

    currentScanData = body;
    renderResults(body);

    const modal = document.getElementById('history-modal');
    if (modal) modal.classList.add('hidden');

    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (err) {
    showToast(`Không tải được lần quét: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function initApp() {
  const showHistoryBtn = document.getElementById('btn-show-history');
  if (showHistoryBtn) {
    showHistoryBtn.addEventListener('click', () => {
      const modal = document.getElementById('history-modal');
      if (modal) modal.classList.remove('hidden');
      loadHistoryList();
    });
  }

  const closeHistoryBtn = document.getElementById('btn-close-history');
  if (closeHistoryBtn) {
    closeHistoryBtn.addEventListener('click', () => {
      const modal = document.getElementById('history-modal');
      if (modal) modal.classList.add('hidden');
    });
  }

  const modal = document.getElementById('history-modal');
  if (modal) {
    modal.addEventListener('click', (event) => {
      if (event.target === modal) modal.classList.add('hidden');
    });
  }

  const targetInput = document.getElementById('target-url');
  if (targetInput) {
    targetInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        startScan();
      }
    });
  }

  // R7-C2: delegated copy handler (no inline onclick in generated markup).
  const msfList = document.getElementById('msf-list');
  if (msfList) {
    msfList.addEventListener('click', (event) => {
      const button = event.target.closest('.msf-copy-btn');
      if (!button) return;
      copyMsfCommand(button.getAttribute('data-msf-id'));
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}

// ---------------------------------------------------------------------------
// Metasploit rendering (kept verbatim from the previous app.js)
// ---------------------------------------------------------------------------
function renderMetasploitSuggestions(suggestions) {
  const container = document.getElementById('msf-list');
  const toggleCheckbox = document.getElementById('toggle-intrusive-msf');
  const showIntrusive = toggleCheckbox ? toggleCheckbox.checked : false;

  container.innerHTML = '';
  window.msfCommandMap = {}; // Reset map

  // R7-B1: keep the visible count and hidden-intrusive note in sync.
  updateMsfBadges(suggestions);

  if (!suggestions || suggestions.length === 0) {
    container.innerHTML = `
      <div class="text-center py-12 bg-cyber-800/40 rounded-xl border border-cyber-700">
        <i data-lucide="check-circle-2" class="w-12 h-12 text-slate-500 mx-auto mb-2"></i>
        <p class="text-slate-400 text-sm">Không có đề xuất Metasploit cho mục tiêu này.</p>
      </div>
    `;
    if (window.lucide) lucide.createIcons();
    return;
  }

  // Populate map for ALL suggestions (so copy works after toggle)
  suggestions.forEach(msf => {
    window.msfCommandMap[msf.id] = msf.verification_command;
  });

  // Split into normal and intrusive
  const normalSuggestions = suggestions.filter(s => !s.intrusive);
  const intrusiveSuggestions = suggestions.filter(s => s.intrusive);

  const cardsToRender = showIntrusive ? [...normalSuggestions, ...intrusiveSuggestions] : normalSuggestions;

  if (cardsToRender.length === 0) {
    container.innerHTML = `
      <div class="text-center py-12 bg-cyber-800/40 rounded-xl border border-cyber-700">
        <p class="text-slate-400 text-sm">Không có module an toàn nào được đề xuất. (Có ${intrusiveSuggestions.length} module intrusive bị ẩn).</p>
      </div>
    `;
    if (window.lucide) lucide.createIcons();
    return;
  }

  cardsToRender.forEach((msf) => {
    const card = document.createElement('div');
    card.className = `bg-cyber-800 border ${msf.intrusive ? 'border-red-800/60' : 'border-purple-900/40'} hover:border-purple-600/60 rounded-xl p-5 space-y-3 transition shadow-lg relative overflow-hidden`;
    
    const intrusiveBadge = msf.intrusive 
      ? `<span class="text-[11px] px-2.5 py-0.5 rounded-full bg-red-950 text-red-400 border border-red-800 font-bold flex items-center gap-1"><i data-lucide="alert-triangle" class="w-3 h-3"></i> INTRUSIVE</span>` 
      : '';

    card.innerHTML = `
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-700/60 pb-3">
        <div class="flex items-center gap-2">
          <span class="p-2 rounded-lg ${msf.intrusive ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-purple-950 text-purple-400 border border-purple-800/80'}">
            <i data-lucide="${msf.intrusive ? 'alert-octagon' : 'terminal'}" class="w-4 h-4"></i>
          </span>
          <div>
            <h4 class="font-bold text-white text-sm">${escapeHtml(msf.title)}</h4>
            <span class="font-mono text-xs text-purple-400">${escapeHtml(msf.module_path)}</span>
          </div>
        </div>
        <div class="flex items-center gap-2 flex-wrap">
          ${intrusiveBadge}
          <span class="text-[11px] px-2.5 py-0.5 rounded-full bg-cyber-700 text-slate-300 border border-cyber-600 font-mono">${escapeHtml(msf.module_type)}</span>
          <span class="text-[11px] px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800">Độ tin cậy: ${escapeHtml(msf.confidence)}</span>
        </div>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(msf.description)}</p>
      ${msf.intrusive ? `
        <div class="bg-red-950/30 border border-red-800/50 rounded-lg p-3 text-xs text-red-300 flex items-start gap-2">
          <i data-lucide="shield-alert" class="w-4 h-4 shrink-0 mt-0.5"></i>
          <span><strong>CẢNH BÁO:</strong> Module này gửi yêu cầu chủ động hoặc thử đăng nhập (brute-force). Chỉ sử dụng khi có sự cho phép rõ ràng bằng văn bản. Không tự động chạy.</span>
        </div>
      ` : ''}
      <div class="text-xs flex items-center gap-2 text-slate-400 bg-cyber-900/60 px-3 py-2 rounded-lg border border-cyber-700">
        <i data-lucide="alert-circle" class="w-3.5 h-3.5 text-cyan-400 shrink-0"></i>
        <span><strong>Lý do kích hoạt:</strong> ${escapeHtml(msf.trigger_reason)}</span>
      </div>
      <div class="space-y-1.5">
        <div class="flex items-center justify-between text-xs text-slate-400">
          <span class="flex items-center gap-1 font-semibold text-slate-300">
            <i data-lucide="command" class="w-3.5 h-3.5 text-purple-400"></i> Lệnh kiểm thử:
          </span>
          <button class="msf-copy-btn text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 font-semibold px-2 py-0.5 rounded bg-purple-950/60 border border-purple-800 hover:bg-purple-900/80 transition" data-msf-id="${escapeHtml(msf.id)}">
            <i data-lucide="copy" class="w-3.5 h-3.5"></i> Sao chép
          </button>
        </div>
        <div class="p-3 bg-black/60 rounded-lg border ${msf.intrusive ? 'border-red-900/40' : 'border-purple-900/40'} text-emerald-400 font-mono text-xs overflow-x-auto select-all">
          ${escapeHtml(msf.verification_command)}
        </div>
      </div>
    `;
    container.appendChild(card);
  });

  if (window.lucide) lucide.createIcons();
}

// Hàm xử lý sự kiện toggle (gọi từ index.html)
function onToggleIntrusiveMsf() {
  if (currentScanData) {
    updateMsfBadges(currentScanData.metasploit_suggestions);
    renderMetasploitSuggestions(currentScanData.metasploit_suggestions);
  }
}
