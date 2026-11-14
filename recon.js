// ============================================================
// SUBDOMAIN RECON MODULE — AegisWeb v1.2.1
// ============================================================

let currentReconData = null;
let selectedSubdomains = new Set();
let isBatchScanning = false;

function toggleReconPanel() {
  const body = document.getElementById('recon-panel-body');
  const chevron = document.getElementById('recon-panel-chevron');
  const label = document.getElementById('recon-panel-label');

  const isHidden = body.classList.contains('hidden');
  body.classList.toggle('hidden', !isHidden);
  if (chevron) chevron.style.transform = isHidden ? 'rotate(180deg)' : '';
  if (label) label.textContent = isHidden ? 'Thu gọn' : 'Mở rộng';
  if (window.lucide) lucide.createIcons();
}

function switchReconTab(tabId) {
  document.querySelectorAll('.recon-tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.recon-tab-btn').forEach(btn => {
    btn.classList.remove('border-b-2', 'border-indigo-500', 'text-indigo-400', 'bg-cyber-800');
    btn.classList.add('text-slate-400');
  });

  const activeContent = document.getElementById(tabId);
  if (activeContent) activeContent.classList.remove('hidden');

  const activeBtn = document.getElementById(`btn-${tabId}`);
  if (activeBtn) {
    activeBtn.classList.remove('text-slate-400');
    activeBtn.classList.add('border-b-2', 'border-indigo-500', 'text-indigo-400', 'bg-cyber-800');
  }
}

function autofillReconDomain(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    const hostname = u.hostname.replace(/^www\./i, '');
    const reconInput = document.getElementById('recon-domain');
    if (reconInput) reconInput.value = hostname;
  } catch (e) {}
}

// R4-10: Full startRecon with confirm_domain
async function startRecon() {
  if (isBatchScanning) {
    showToast('⚠️ Đang có tiến trình quét hàng loạt đang chạy, vui lòng chờ hoàn tất!');
    return;
  }

  const domainInput = document.getElementById('recon-domain');
  let domain = (domainInput ? domainInput.value : '').trim();

  domain = domain.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].replace(/^www\./i, '').trim();
  if (domainInput) domainInput.value = domain;

  const consentEl = document.getElementById('recon-consent');
  const consent = consentEl ? consentEl.checked : false;

  if (!domain) {
    showToast('Vui lòng nhập domain cần phân tích!');
    return;
  }
  if (!consent) {
    showToast('⚠️ Bạn cần xác nhận quyền kiểm thử (Scope Gate) trước khi tiếp tục!');
    return;
  }

  const btnRecon = document.getElementById('btn-recon');
  const progressEl = document.getElementById('recon-progress');
  const summaryBar = document.getElementById('recon-summary-bar');
  const tabsArea = document.getElementById('recon-tabs-area');
  const statusText = document.getElementById('recon-status-text');

  summaryBar.classList.add('hidden');
  tabsArea.classList.add('hidden');
  selectedSubdomains.clear();
  updateSelectedCount();

  btnRecon.disabled = true;
  progressEl.classList.remove('hidden');

  const steps = [
    'Truy vấn Certificate Transparency logs (crt.sh)...',
    'Kiểm tra Wildcard DNS và phân giải từng subdomain...',
    'Phân tích CNAME và phát hiện nguy cơ Subdomain Takeover...',
    'Kiểm tra cấu hình DNS và bảo mật Email (SPF, DMARC, CAA)...',
  ];
  let stepIdx = 0;
  const stepTimer = setInterval(() => {
    stepIdx = (stepIdx + 1) % steps.length;
    if (statusText) statusText.textContent = steps[stepIdx];
  }, 3000);

  try {
    const resp = await fetch('/api/recon', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // R4-10: Gửi đầy đủ domain, consent, confirm_domain
      body: JSON.stringify({ domain, consent, confirm_domain: domain, max_concurrent: 8 }),
    });

    clearInterval(stepTimer);

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: 'Lỗi server không xác định' }));
      throw new Error(err.detail || 'Recon thất bại');
    }

    const data = await resp.json();
    currentReconData = data;
    renderReconResults(data);

  } catch (err) {
    clearInterval(stepTimer);
    showToast(`❌ Lỗi: ${err.message}`);
  } finally {
    progressEl.classList.add('hidden');
    btnRecon.disabled = false;
  }
}

function renderReconResults(data) {
  const summaryBar = document.getElementById('recon-summary-bar');
  const tabsArea = document.getElementById('recon-tabs-area');

  document.getElementById('recon-count-discovered').textContent = data.total_discovered || 0;
  document.getElementById('recon-count-alive').textContent = data.total_alive || 0;
  document.getElementById('recon-count-takeover').textContent = (data.takeover_findings || []).length;
  document.getElementById('recon-count-dns').textContent = (data.dns_findings || []).length;

  document.getElementById('badge-rtab-takeover').textContent = (data.takeover_findings || []).length;
  document.getElementById('badge-rtab-dns').textContent = (data.dns_findings || []).length;

  const wildcardWarn = document.getElementById('wildcard-warning');
  if (wildcardWarn) {
    if (data.is_wildcard && data.wildcard_ips) {
      document.getElementById('wildcard-warning-text').textContent =
        `⚠️ Phát hiện Wildcard DNS (*.${data.domain} → ${data.wildcard_ips.join(', ')}). Các subdomain có IP trùng với Wildcard đã được lọc ra.`;
      wildcardWarn.classList.remove('hidden');
    } else {
      wildcardWarn.classList.add('hidden');
    }
  }

  const crtshWarn = document.getElementById('crtsh-warning');
  if (crtshWarn) {
    if (data.crtsh_error) {
      document.getElementById('crtsh-warning-text').textContent =
        `Cảnh báo kết nối Certificate Transparency (crt.sh): ${data.crtsh_error}.`;
      crtshWarn.classList.remove('hidden');
    } else {
      crtshWarn.classList.add('hidden');
    }
  }

  renderReconDiff(data.diff);
  renderSubdomainList(data.subdomains || []);
  renderTakeoverList(data.takeover_findings || []);
  renderDnsFindingList(data.dns_findings || [], data.registrable_domain || data.domain);

  summaryBar.classList.remove('hidden');
  tabsArea.classList.remove('hidden');
  switchReconTab('rtab-subdomains');
  if (window.lucide) lucide.createIcons();
}

function renderReconDiff(diff) {
  const banner = document.getElementById('recon-diff-banner');
  if (!banner) return;
  if (!diff || !diff.has_previous) {
    banner.classList.add('hidden');
    banner.innerHTML = '';
    return;
  }

  const newCount = diff.new_subdomains?.length || 0;
  const removedCount = diff.removed_subdomains?.length || 0;
  const newTakeovers = diff.new_takeovers?.length || 0;

  banner.innerHTML = `
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-indigo-800/50 pb-2 mb-2">
      <div class="flex items-center gap-2">
        <i data-lucide="history" class="w-4 h-4 text-indigo-400"></i>
        <strong class="text-white">Theo dõi biến động Subdomain</strong>
        <span class="text-[10px] px-2 py-0.5 rounded-full bg-indigo-900/60 text-indigo-300 border border-indigo-700">So với: ${escapeHtml(diff.previous_scan_time || 'lần trước')}</span>
      </div>
      <div class="text-[11px] text-slate-400">Lần trước: <span class="font-mono text-white">${diff.previous_total}</span></div>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
      <div class="p-2 rounded bg-indigo-900/40 border border-indigo-800/40">
        <span class="text-emerald-400 font-semibold block">+ ${newCount} Subdomain mới:</span>
        ${newCount > 0 ? `<div class="truncate text-slate-300 mt-0.5">${diff.new_subdomains.slice(0, 3).map(s => escapeHtml(s)).join(', ')}${newCount > 3 ? '...' : ''}</div>` : '<span class="text-slate-500">Không có</span>'}
      </div>
      <div class="p-2 rounded bg-indigo-900/40 border border-indigo-800/40">
        <span class="text-slate-400 font-semibold block">- ${removedCount} Subdomain đã gỡ:</span>
        ${removedCount > 0 ? `<div class="truncate text-slate-400 mt-0.5">${diff.removed_subdomains.slice(0, 3).map(s => escapeHtml(s)).join(', ')}${removedCount > 3 ? '...' : ''}</div>` : '<span class="text-slate-500">Không có</span>'}
      </div>
      <div class="p-2 rounded bg-indigo-900/40 border border-indigo-800/40">
        <span class="text-red-400 font-semibold block">⚠️ Takeover mới phát sinh:</span>
        <span class="${newTakeovers > 0 ? 'text-red-400 font-bold' : 'text-slate-500'}">${newTakeovers} nguy cơ</span>
      </div>
    </div>
  `;
  banner.classList.remove('hidden');
}

function renderSubdomainList(subdomains) {
  const container = document.getElementById('subdomain-list-container');
  if (!container) return;

  container.innerHTML = '';
  selectedSubdomains.clear();
  updateSelectedCount();

  const selectAllCheckbox = document.getElementById('recon-select-all');
  if (selectAllCheckbox) selectAllCheckbox.checked = false;

  if (!subdomains || subdomains.length === 0) {
    container.innerHTML = `<div class="text-center py-8 text-slate-500 text-xs">Không tìm thấy subdomain nào.</div>`;
    return;
  }

  subdomains.forEach((sub) => {
    const isFiltered = sub.wildcard_filtered;
    const isAlive = sub.alive && !isFiltered;

    const row = document.createElement('div');
    row.className = `flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border transition text-xs
      ${isAlive ? 'bg-cyber-800 border-cyber-700 hover:border-indigo-700' : 'bg-cyber-900/40 border-cyber-800/60 opacity-60'}`;

    const ipsText = sub.ip_addresses?.join(', ') || 'Không phân giải được';
    const cnameText = sub.cname ? `→ ${sub.cname}` : '';

    row.innerHTML = `
      <div class="flex items-center gap-3 flex-1 min-w-0">
        ${isAlive ? `<input type="checkbox" data-subdomain="${escapeHtml(sub.subdomain)}" class="sub-checkbox rounded border-cyber-600 bg-cyber-900 text-indigo-500 focus:ring-0">` : `<span class="w-3"></span>`}
        <span class="w-2 h-2 rounded-full shrink-0 ${isAlive ? 'bg-emerald-400' : isFiltered ? 'bg-yellow-500' : 'bg-slate-600'}"></span>
        <span class="font-mono font-medium ${isAlive ? 'text-white' : 'text-slate-500'} truncate">${escapeHtml(sub.subdomain)}</span>
        ${sub.cname ? `<span class="text-slate-500 truncate text-[10px]">${escapeHtml(cnameText)}</span>` : ''}
        ${isFiltered ? `<span class="px-1.5 py-0.5 rounded bg-yellow-950 text-yellow-400 border border-yellow-800 text-[10px]">Wildcard</span>` : ''}
      </div>
      <div class="flex items-center gap-3 text-slate-500 shrink-0">
        <span class="font-mono text-[11px]">${escapeHtml(ipsText)}</span>
        ${isAlive ? `
          <button type="button" data-subdomain="${escapeHtml(sub.subdomain)}" class="btn-scan-single px-2.5 py-1 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 hover:bg-indigo-900 transition flex items-center gap-1">
            <i data-lucide="radar" class="w-3 h-3 pointer-events-none"></i> Quét
          </button>
        ` : ''}
      </div>
    `;
    container.appendChild(row);
  });

  container.onchange = (e) => {
    if (e.target && e.target.classList.contains('sub-checkbox')) {
      const sub = e.target.getAttribute('data-subdomain');
      if (sub) toggleSubdomainSelection(sub, e.target.checked);
    }
  };

  container.onclick = (e) => {
    const btn = e.target.closest('.btn-scan-single');
    if (btn) {
      const sub = btn.getAttribute('data-subdomain');
      if (sub) scanSubdomain(`https://${sub}`);
    }
  };

  if (window.lucide) lucide.createIcons();
}

function toggleSubdomainSelection(subdomain, checked) {
  if (checked) {
    selectedSubdomains.add(subdomain);
    const allCbs = document.querySelectorAll('.sub-checkbox');
    if (allCbs.length > 0 && selectedSubdomains.size >= allCbs.length) {
      const selectAll = document.getElementById('recon-select-all');
      if (selectAll) selectAll.checked = true;
    }
  } else {
    selectedSubdomains.delete(subdomain);
    const selectAll = document.getElementById('recon-select-all');
    if (selectAll) selectAll.checked = false;
  }
  updateSelectedCount();
}

function toggleSelectAllSubdomains(checked) {
  const checkboxes = document.querySelectorAll('.sub-checkbox');
  checkboxes.forEach(cb => {
    cb.checked = checked;
    const sub = cb.getAttribute('data-subdomain');
    if (checked && sub) selectedSubdomains.add(sub);
  });
  if (!checked) selectedSubdomains.clear();
  updateSelectedCount();
}

function updateSelectedCount() {
  const countEl = document.getElementById('recon-selected-count');
  const btnBatch = document.getElementById('btn-batch-scan');
  if (countEl) countEl.textContent = `(${selectedSubdomains.size} đã chọn)`;
  if (btnBatch) btnBatch.disabled = (selectedSubdomains.size === 0 || isBatchScanning);
}

function scanSubdomain(url) {
  const targetInput = document.getElementById('target-url');
  if (targetInput) targetInput.value = url;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(() => {
    if (typeof startScan === 'function') startScan();
  }, 300);
}

// R4-9: Batch Scan with strict consent and no client fallback
async function startBatchScan() {
  if (selectedSubdomains.size === 0 || isBatchScanning) return;

  const consentEl = document.getElementById('recon-consent');
  if (!consentEl || !consentEl.checked) {
    showToast('⚠️ Bạn cần tick xác nhận phạm vi kiểm thử trước khi quét hàng loạt!');
    return;
  }

  if (!currentReconData || !currentReconData.recon_id) {
    showToast('❌ Thiếu recon_id. Vui lòng khám phá subdomain lại trước khi quét hàng loạt.');
    return;
  }

  const targets = Array.from(selectedSubdomains);
  isBatchScanning = true;
  updateSelectedCount();

  const progressBox = document.getElementById('batch-scan-progress');
  const progressText = document.getElementById('batch-progress-text');
  const percentText = document.getElementById('batch-progress-percent');
  const progressBarFill = document.getElementById('batch-progress-bar-fill');

  progressBox.classList.remove('hidden');
  progressBarFill.style.width = '10%';
  percentText.textContent = '10%';
  progressText.textContent = `Đang khởi tạo phiên quét cho ${targets.length} subdomain...`;

  showToast(`⚡ Bắt đầu quét ${targets.length} subdomain qua máy chủ...`);

  try {
    progressBarFill.style.width = '40%';
    percentText.textContent = '40%';
    progressText.textContent = `Đang quét đồng thời qua máy chủ AegisWeb...`;

    const resp = await fetch(`/api/recon/${encodeURIComponent(currentReconData.recon_id)}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subdomains: targets, confirm_scope: true, max_concurrent: 5 })
    });

    if (!resp.ok) {
      const errJson = await resp.json().catch(() => ({ detail: 'Lỗi server khi batch scan' }));
      if (resp.status === 400) {
        throw new Error(`Giới hạn quét: ${errJson.detail || 'Vượt quá 50 targets. Hãy chọn tối đa 50 subdomain trong danh sách.'}`);
      } else if (resp.status === 403) {
        throw new Error(`Từ chối: ${errJson.detail || 'Bạn cần xác nhận phạm vi.'}`);
      } else {
        throw new Error(errJson.detail || 'Quét hàng loạt thất bại');
      }
    }

    const resData = await resp.json();
    const completedCount = resData.completed || 0;
    const failedCount = resData.failed || 0;

    progressBarFill.style.width = '100%';
    percentText.textContent = '100%';

    if (failedCount > 0) {
      progressText.textContent = `Hoàn tất: ${completedCount} thành công, ${failedCount} thất bại.`;
      showToast(`⚠️ ${completedCount} thành công, ${failedCount} thất bại.`);
    } else {
      progressText.textContent = `Đã hoàn tất ${completedCount}/${targets.length} subdomain!`;
      showToast(`✅ Đã hoàn tất ${completedCount} subdomain!`);
    }

  } catch (err) {
    showToast(`❌ Lỗi: ${err.message}`);
    progressText.textContent = `Gặp sự cố: ${err.message}`;
  } finally {
    setTimeout(() => {
      progressBox.classList.add('hidden');
      isBatchScanning = false;
      updateSelectedCount();
      if (typeof loadHistoryList === 'function') loadHistoryList();
    }, 2500);
  }
}

function renderTakeoverList(findings) {
  const container = document.getElementById('takeover-list-container');
  if (!container) return;
  container.innerHTML = '';

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <div class="text-center py-10 bg-cyber-800/40 rounded-xl border border-cyber-700">
        <i data-lucide="shield-check" class="w-10 h-10 text-emerald-500 mx-auto mb-2"></i>
        <p class="text-slate-400 text-sm">Không phát hiện dấu hiệu Subdomain Takeover.</p>
      </div>`;
    if (window.lucide) lucide.createIcons();
    return;
  }

  findings.forEach(f => {
    const card = document.createElement('div');
    card.className = 'bg-red-950/30 border border-red-800/50 rounded-xl p-5 space-y-3';
    card.innerHTML = `
      <div class="flex items-start gap-3">
        <span class="p-2 rounded-lg bg-red-950 border border-red-800 text-red-400 shrink-0">
          <i data-lucide="shield-x" class="w-4 h-4"></i>
        </span>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-xs font-bold px-2 py-0.5 rounded-full bg-red-950 text-red-400 border border-red-800 uppercase">${escapeHtml(f.severity || 'HIGH')}</span>
            <h4 class="font-bold text-white text-sm">${escapeHtml(f.title || '')}</h4>
          </div>
          <p class="text-xs text-slate-300 mt-1 leading-relaxed">${escapeHtml(f.description || '')}</p>
        </div>
      </div>
      ${f.evidence ? `<div class="bg-black/40 rounded-lg p-2.5 border border-red-900/30 font-mono text-xs text-amber-300">${escapeHtml(f.evidence)}</div>` : ''}
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
    `;
    container.appendChild(card);
  });
  if (window.lucide) lucide.createIcons();
}

function renderDnsFindingList(findings, apexDomain) {
  const container = document.getElementById('dns-list-container');
  if (!container) return;
  container.innerHTML = '';

  const apexBanner = document.createElement('div');
  apexBanner.className = 'mb-3 bg-cyber-900/80 border border-cyan-800/40 rounded-xl p-3 text-xs flex items-center justify-between gap-2';
  apexBanner.innerHTML = `
    <div class="flex items-center gap-2 text-slate-300">
      <i data-lucide="info" class="w-4 h-4 text-cyan-400 shrink-0"></i>
      <span>Các bản ghi SPF, DMARC, CAA & DNSSEC được kiểm tra trên Apex Domain: <strong class="font-mono text-cyan-300">${escapeHtml(apexDomain || '')}</strong></span>
    </div>
    <span class="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 shrink-0">RFC Validated</span>
  `;
  container.appendChild(apexBanner);

  if (!findings || findings.length === 0) {
    const okBox = document.createElement('div');
    okBox.className = 'text-center py-10 bg-cyber-800/40 rounded-xl border border-cyber-700';
    okBox.innerHTML = `
      <i data-lucide="check-circle-2" class="w-10 h-10 text-emerald-500 mx-auto mb-2"></i>
      <p class="text-slate-400 text-sm">Cấu hình DNS & Email Security trên ${escapeHtml(apexDomain || 'domain')} trông ổn.</p>
    `;
    container.appendChild(okBox);
    if (window.lucide) lucide.createIcons();
    return;
  }

  findings.forEach(f => {
    const badgeClass = typeof getSeverityBadge === 'function' ? getSeverityBadge(f.severity) : 'bg-amber-950 text-amber-400 border border-amber-800';
    const borderClass = typeof getSeverityBorder === 'function' ? getSeverityBorder(f.severity) : 'border-cyber-700';
    const card = document.createElement('div');
    card.className = `bg-cyber-800 border ${borderClass} rounded-xl p-4 space-y-2`;
    card.innerHTML = `
      <div class="flex items-center gap-2 flex-wrap">
        <span class="${badgeClass} px-2.5 py-0.5 rounded-full text-xs font-bold uppercase">${escapeHtml(f.severity || 'INFO')}</span>
        <h4 class="font-bold text-white text-sm">${escapeHtml(f.title || '')}</h4>
        <span class="text-[11px] px-2 py-0.5 rounded bg-cyber-700 text-slate-400 border border-cyber-600">Apex: ${escapeHtml(apexDomain || '')}</span>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(f.description || '')}</p>
      ${f.evidence ? `<div class="bg-black/40 rounded p-2 font-mono text-xs text-amber-300 border border-cyber-700">${escapeHtml(f.evidence)}</div>` : ''}
      <div class="text-xs text-emerald-300 bg-emerald-950/20 border border-emerald-900/30 rounded-lg p-2.5">
        <strong>Khắc phục:</strong> ${escapeHtml(f.remediation || '')}
      </div>
    `;
    container.appendChild(card);
  });

  if (window.lucide) lucide.createIcons();
}