// Vulnerability Management Dashboard JS

// ==========================================
// Security: HTML Escaping to prevent XSS
// ==========================================

/**
 * Escape HTML special characters to prevent XSS attacks.
 * @param {string} str - The string to escape
 * @returns {string} - The escaped string safe for HTML insertion
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

/**
 * Validate and sanitize URLs to prevent javascript: and data: injection.
 * Only allows http:, https:, and relative URLs.
 * @param {string} url - The URL to validate
 * @returns {string} - The safe URL or empty string if invalid
 */
function sanitizeUrl(url) {
  if (!url) return '';
  const str = String(url).trim();
  // Only allow http, https, or relative URLs (starting with /)
  if (str.startsWith('http://') || str.startsWith('https://') || str.startsWith('/')) {
    return escapeHtml(str);
  }
  // Block javascript:, data:, vbscript:, etc.
  return '';
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  loadEffectiveDate();
  loadStats();
  loadApproachingSLA();
  loadVulnerabilities();
  loadAcceptedVulns();
  loadImports();
  loadLogs();
});

// ==========================================
// Time Simulation Functions
// ==========================================

// Load and display the current effective date
async function loadEffectiveDate() {
  try {
    const res = await fetch('/api/simulation/date');
    const data = await res.json();

    const dateStr = data.effective_date.split('T')[0];
    document.getElementById('effective-date').textContent = dateStr;
    document.getElementById('sim-date-input').value = dateStr;

    const badge = document.getElementById('simulation-badge');
    if (data.simulated) {
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  } catch (err) {
    console.error('Failed to load effective date:', err);
  }
}

// Set simulated date from input
async function setSimulatedDate() {
  const dateInput = document.getElementById('sim-date-input').value;
  if (!dateInput) {
    alert('Please select a date');
    return;
  }

  try {
    const res = await fetch('/api/simulation/date', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ date: dateInput })
    });

    if (!res.ok) throw new Error('Failed to set date');

    // Refresh everything
    await loadEffectiveDate();
    loadStats();
    loadApproachingSLA();
    loadVulnerabilities();
  } catch (err) {
    alert('Failed to set simulated date: ' + err.message);
  }
}

// Clear simulated date (return to real time)
async function clearSimulatedDate() {
  try {
    const res = await fetch('/api/simulation/date', {
      method: 'DELETE'
    });

    if (!res.ok) throw new Error('Failed to clear date');

    // Refresh everything
    await loadEffectiveDate();
    loadStats();
    loadApproachingSLA();
    loadVulnerabilities();
  } catch (err) {
    alert('Failed to clear simulated date: ' + err.message);
  }
}

// Advance the date by N days
async function advanceDay(days) {
  try {
    // Get current effective date
    const res = await fetch('/api/simulation/date');
    const data = await res.json();

    // Parse and advance
    const current = new Date(data.effective_date);
    current.setDate(current.getDate() + days);
    const newDate = current.toISOString().split('T')[0];

    // Set new date
    await fetch('/api/simulation/date', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ date: newDate })
    });

    // Refresh everything
    await loadEffectiveDate();
    loadStats();
    loadApproachingSLA();
    loadVulnerabilities();
  } catch (err) {
    alert('Failed to advance date: ' + err.message);
  }
}

// Load statistics
async function loadStats() {
  try {
    const res = await fetch('/api/vulnerabilities/stats');
    const stats = await res.json();

    document.getElementById('stat-critical').textContent = stats.critical;
    document.getElementById('stat-high').textContent = stats.high;
    document.getElementById('stat-medium').textContent = stats.medium;
    document.getElementById('stat-low').textContent = stats.low;
    document.getElementById('stat-total').textContent = stats.total_open;
    document.getElementById('stat-risk-accepted').textContent = stats.risk_accepted;
    document.getElementById('stat-resolved').textContent = stats.resolved;
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

// Load vulnerabilities approaching SLA
async function loadApproachingSLA() {
  try {
    const res = await fetch('/api/vulnerabilities/?approaching_sla=true&limit=10');
    const vulns = await res.json();

    const list = document.getElementById('sla-list');
    if (vulns.length === 0) {
      list.innerHTML = '<p class="text-green-600">No vulnerabilities approaching SLA deadline</p>';
      return;
    }

    list.innerHTML = vulns.map(v => `
      <div class="flex justify-between items-center bg-white rounded p-2">
        <div>
          <span class="px-2 py-1 rounded text-xs font-bold severity-${escapeHtml(v.severity)}">${escapeHtml(v.severity).toUpperCase()}</span>
          <span class="ml-2 font-medium">${escapeHtml(v.cve) || 'No CVE'}</span>
          <span class="text-gray-500">on ${escapeHtml(v.host)}</span>
        </div>
        <div class="text-right">
          <span class="text-red-600 font-bold">${escapeHtml(v.days_remaining)} days left</span>
          ${v.jira_ticket_url ? `<a href="${sanitizeUrl(v.jira_ticket_url)}" target="_blank" rel="noopener noreferrer" class="ml-2 text-blue-600">${escapeHtml(v.jira_ticket_id)}</a>` : ''}
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load SLA warnings:', err);
  }
}

// Load vulnerabilities list
async function loadVulnerabilities() {
  try {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const host = document.getElementById('filter-host').value;

    let url = '/api/vulnerabilities/?limit=50';
    if (severity) url += `&severity=${severity}`;
    if (status) url += `&status=${status}`;
    if (host) url += `&host=${encodeURIComponent(host)}`;

    const res = await fetch(url);
    const vulns = await res.json();

    const table = document.getElementById('vuln-table');
    if (vulns.length === 0) {
      table.innerHTML = '<p class="text-gray-500">No vulnerabilities found</p>';
      return;
    }

    table.innerHTML = `
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-2 text-left">Severity</th>
            <th class="px-4 py-2 text-left">CVE</th>
            <th class="px-4 py-2 text-left">Host</th>
            <th class="px-4 py-2 text-left">Title</th>
            <th class="px-4 py-2 text-left">Status</th>
            <th class="px-4 py-2 text-left">SLA</th>
            <th class="px-4 py-2 text-left">Jira</th>
            <th class="px-4 py-2 text-left">Jira Status</th>
            <th class="px-4 py-2 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${vulns.map(v => `
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-2">
                <span class="px-2 py-1 rounded text-xs font-bold severity-${escapeHtml(v.severity)}">${escapeHtml(v.severity).toUpperCase()}</span>
              </td>
              <td class="px-4 py-2 font-mono text-sm">${escapeHtml(v.cve) || '-'}</td>
              <td class="px-4 py-2">${escapeHtml(v.host)}</td>
              <td class="px-4 py-2 max-w-xs truncate" title="${escapeHtml(v.title)}"><a href="#" onclick="openDetailModal('${escapeHtml(v.id)}'); return false;" class="text-blue-600 hover:underline">${escapeHtml(v.title)}</a></td>
              <td class="px-4 py-2">
                <span class="px-2 py-1 bg-gray-100 rounded text-xs">${escapeHtml(v.status)}</span>
              </td>
              <td class="px-4 py-2 ${v.days_remaining < 0 ? 'text-red-600 font-bold' : v.days_remaining < 7 ? 'text-amber-600' : ''}">
                ${v.days_remaining !== null ? escapeHtml(v.days_remaining) + 'd' : '-'}
              </td>
              <td class="px-4 py-2">
                ${v.jira_ticket_url ? `<a href="${sanitizeUrl(v.jira_ticket_url)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline">${escapeHtml(v.jira_ticket_id)}</a>` : '-'}
              </td>
              <td class="px-4 py-2 text-sm">${escapeHtml(v.jira_status) || '-'}</td>
              <td class="px-4 py-2">
                <div class="flex gap-1">
                  ${v.status !== 'accepted_risk' && v.status !== 'resolved' ? `<button onclick="openRiskModal('${escapeHtml(v.id)}')" class="text-xs px-2 py-1 bg-purple-100 text-purple-700 rounded hover:bg-purple-200" title="Accept Risk">Accept</button>` : ''}
                  ${v.jira_ticket_id ? `<button onclick="syncJira('${escapeHtml(v.id)}')" class="text-xs px-2 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200" title="Sync Jira">Sync</button>` : ''}
                  <button onclick="deleteVuln('${escapeHtml(v.id)}')" class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200" title="Delete">Del</button>
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error('Failed to load vulnerabilities:', err);
  }
}

// Load import history
async function loadImports() {
  try {
    const res = await fetch('/api/imports/');
    const imports = await res.json();

    const list = document.getElementById('imports-list');
    if (imports.length === 0) {
      list.innerHTML = '<p class="text-gray-500">No imports yet</p>';
      return;
    }

    list.innerHTML = `
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-2 text-left">Date</th>
            <th class="px-4 py-2 text-left">File</th>
            <th class="px-4 py-2 text-left">Scanner</th>
            <th class="px-4 py-2 text-left">New</th>
            <th class="px-4 py-2 text-left">Existing</th>
            <th class="px-4 py-2 text-left">Resolved</th>
          </tr>
        </thead>
        <tbody>
          ${imports.map(i => `
            <tr class="border-t">
              <td class="px-4 py-2">${escapeHtml(new Date(i.imported_at).toLocaleString())}</td>
              <td class="px-4 py-2">${escapeHtml(i.filename)}</td>
              <td class="px-4 py-2 capitalize">${escapeHtml(i.scanner)}</td>
              <td class="px-4 py-2 text-green-600">+${escapeHtml(i.new_count)}</td>
              <td class="px-4 py-2">${escapeHtml(i.existing_count)}</td>
              <td class="px-4 py-2 text-blue-600">${escapeHtml(i.resolved_count)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error('Failed to load imports:', err);
  }
}

// Load AI insights
async function loadInsights() {
  const content = document.getElementById('insights-content');
  content.innerHTML = '<p class="text-gray-500">Generating insights...</p>';

  try {
    const res = await fetch('/api/insights/');
    const insights = await res.json();

    if (insights.error) {
      content.innerHTML = `<p class="text-red-600">${escapeHtml(insights.error)}</p>`;
      return;
    }

    let html = '';

    if (insights.patterns && insights.patterns.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Patterns Detected</h3>
          ${insights.patterns.map(p => `
            <div class="bg-gray-50 rounded p-3 mb-2">
              <div class="font-medium">${escapeHtml(p.type).replace(/_/g, ' ').toUpperCase()}</div>
              <p>${escapeHtml(p.description)}</p>
              <p class="text-sm text-gray-600">Recommendation: ${escapeHtml(p.recommendation)}</p>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.training_opportunities && insights.training_opportunities.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Training Opportunities</h3>
          ${insights.training_opportunities.map(t => `
            <div class="bg-blue-50 rounded p-3 mb-2">
              <div class="font-medium">${escapeHtml(t.topic)}</div>
              <p class="text-sm">${escapeHtml(t.reason)} (${escapeHtml(t.affected_count)} affected)</p>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.priority_actions && insights.priority_actions.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Priority Actions</h3>
          ${insights.priority_actions.map(a => `
            <div class="bg-green-50 rounded p-3 mb-2 flex justify-between">
              <span>${escapeHtml(a.action)}</span>
              <span class="text-sm text-gray-600">${escapeHtml(a.impact)} | Effort: ${escapeHtml(a.effort)}</span>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.raw_analysis) {
      html = `<pre class="bg-gray-50 p-4 rounded whitespace-pre-wrap">${escapeHtml(insights.raw_analysis)}</pre>`;
    }

    content.innerHTML = html || '<p class="text-gray-500">No insights available</p>';
  } catch (err) {
    content.innerHTML = `<p class="text-red-600">Failed to load insights: ${escapeHtml(err.message)}</p>`;
  }
}

// Tab switching
function showTab(tab) {
  // Hide all content
  document.querySelectorAll('[id^="content-"]').forEach(el => el.classList.add('hidden'));
  // Reset tab styles
  document.querySelectorAll('[id^="tab-"]').forEach(el => {
    el.classList.remove('border-b-2', 'border-blue-600', 'text-blue-600');
    el.classList.add('text-gray-500');
  });

  // Show selected content
  document.getElementById(`content-${tab}`).classList.remove('hidden');
  // Highlight selected tab
  const tabEl = document.getElementById(`tab-${tab}`);
  tabEl.classList.add('border-b-2', 'border-blue-600', 'text-blue-600');
  tabEl.classList.remove('text-gray-500');
}

// Import modal
function openImportModal() {
  document.getElementById('import-modal').classList.remove('hidden');
  document.getElementById('import-modal').classList.add('flex');
}

function closeImportModal() {
  document.getElementById('import-modal').classList.add('hidden');
  document.getElementById('import-modal').classList.remove('flex');
}

async function submitImport(event) {
  event.preventDefault();

  const form = event.target;
  const formData = new FormData(form);

  try {
    const res = await fetch('/api/imports/upload', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Import failed');
    }

    const result = await res.json();
    alert(`Import complete!\nNew: ${result.new_count}\nExisting: ${result.existing_count}\nResolved: ${result.resolved_count}`);

    closeImportModal();
    form.reset();

    // Refresh data
    loadStats();
    loadApproachingSLA();
    loadVulnerabilities();
    loadImports();
    loadLogs();
  } catch (err) {
    alert('Import failed: ' + err.message);
  }
}

// ==========================================
// Logs Functions
// ==========================================

async function loadLogs() {
  try {
    const res = await fetch('/api/imports/logs');
    const data = await res.json();

    const list = document.getElementById('logs-list');
    if (!data.logs || data.logs.length === 0) {
      list.innerHTML = '<p class="text-gray-400">No logs yet. Import a file to see logs.</p>';
      return;
    }

    list.innerHTML = data.logs.map(log => {
      const levelColor = {
        'INFO': 'text-green-400',
        'WARNING': 'text-yellow-400',
        'ERROR': 'text-red-400'
      }[log.level] || 'text-gray-400';

      const time = escapeHtml(log.timestamp.split('T')[1].split('.')[0]);
      return `<div class="mb-1">
        <span class="text-gray-500">${time}</span>
        <span class="${levelColor}">[${escapeHtml(log.level)}]</span>
        <span class="text-white">${escapeHtml(log.message)}</span>
        ${log.details ? `<span class="text-gray-400"> - ${escapeHtml(log.details)}</span>` : ''}
      </div>`;
    }).join('');
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}

async function clearLogs() {
  try {
    await fetch('/api/imports/logs', { method: 'DELETE' });
    loadLogs();
  } catch (err) {
    console.error('Failed to clear logs:', err);
  }
}

// ==========================================
// Risk Accepted Tab
// ==========================================

async function loadAcceptedVulns() {
  try {
    const res = await fetch('/api/vulnerabilities/?status=accepted_risk&limit=100');
    const vulns = await res.json();

    const table = document.getElementById('accepted-table');
    if (vulns.length === 0) {
      table.innerHTML = '<p class="text-gray-500">No risk-accepted vulnerabilities</p>';
      return;
    }

    table.innerHTML = `
      <table class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-2 text-left">Severity</th>
            <th class="px-4 py-2 text-left">CVE</th>
            <th class="px-4 py-2 text-left">Host</th>
            <th class="px-4 py-2 text-left">Title</th>
            <th class="px-4 py-2 text-left">EGRC #</th>
            <th class="px-4 py-2 text-left">Expiry</th>
            <th class="px-4 py-2 text-left">Jira</th>
            <th class="px-4 py-2 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${vulns.map(v => {
            const expiryDate = v.egrc_expiry_date ? new Date(v.egrc_expiry_date).toLocaleDateString() : '-';
            const isExpired = v.egrc_expiry_date && new Date(v.egrc_expiry_date) < new Date();
            return `
              <tr class="border-t hover:bg-gray-50 ${isExpired ? 'bg-red-50' : ''}">
                <td class="px-4 py-2">
                  <span class="px-2 py-1 rounded text-xs font-bold severity-${escapeHtml(v.severity)}">${escapeHtml(v.severity).toUpperCase()}</span>
                </td>
                <td class="px-4 py-2 font-mono text-sm">${escapeHtml(v.cve) || '-'}</td>
                <td class="px-4 py-2">${escapeHtml(v.host)}</td>
                <td class="px-4 py-2 max-w-xs truncate" title="${escapeHtml(v.title)}"><a href="#" onclick="openDetailModal('${escapeHtml(v.id)}'); return false;" class="text-blue-600 hover:underline">${escapeHtml(v.title)}</a></td>
                <td class="px-4 py-2 font-mono">${escapeHtml(v.egrc_number) || '-'}</td>
                <td class="px-4 py-2 ${isExpired ? 'text-red-600 font-bold' : ''}">${escapeHtml(expiryDate)}</td>
                <td class="px-4 py-2">
                  ${v.jira_ticket_url ? `<a href="${sanitizeUrl(v.jira_ticket_url)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline">${escapeHtml(v.jira_ticket_id)}</a>` : '-'}
                </td>
                <td class="px-4 py-2">
                  <button onclick="deleteVuln('${escapeHtml(v.id)}')" class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200">Del</button>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error('Failed to load accepted vulns:', err);
  }
}

// ==========================================
// Detail Modal
// ==========================================

function openDetailModal(vulnId) {
  document.getElementById('detail-modal').classList.remove('hidden');
  document.getElementById('detail-modal').classList.add('flex');
  loadVulnDetail(vulnId);
}

function closeDetailModal() {
  document.getElementById('detail-modal').classList.add('hidden');
  document.getElementById('detail-modal').classList.remove('flex');
}

async function loadVulnDetail(vulnId) {
  const content = document.getElementById('detail-content');
  content.innerHTML = '<p class="text-gray-500">Loading...</p>';

  try {
    const res = await fetch(`/api/vulnerabilities/${vulnId}`);
    if (!res.ok) throw new Error('Failed to load');
    const v = await res.json();

    content.innerHTML = `
      <div class="grid grid-cols-2 gap-4">
        <div class="col-span-2 bg-gray-50 p-4 rounded">
          <div class="flex items-center gap-2 mb-2">
            <span class="px-2 py-1 rounded text-xs font-bold severity-${escapeHtml(v.severity)}">${escapeHtml(v.severity).toUpperCase()}</span>
            <span class="text-lg font-semibold">${escapeHtml(v.title)}</span>
          </div>
          <p class="text-gray-600">${escapeHtml(v.description) || 'No description available'}</p>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Identification</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">ID:</span> <span class="font-mono">${escapeHtml(v.id)}</span></p>
            <p><span class="text-gray-500">CVE:</span> ${escapeHtml(v.cve) || 'N/A'}</p>
            <p><span class="text-gray-500">Scanner:</span> ${escapeHtml(v.scanner)}</p>
            <p><span class="text-gray-500">Scanner ID:</span> ${escapeHtml(v.scanner_id) || 'N/A'}</p>
          </div>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Target</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">Host:</span> ${escapeHtml(v.host)}</p>
            <p><span class="text-gray-500">Port:</span> ${escapeHtml(v.port) || 'N/A'}</p>
            <p><span class="text-gray-500">Protocol:</span> ${escapeHtml(v.protocol) || 'N/A'}</p>
            <p><span class="text-gray-500">Service:</span> ${escapeHtml(v.service) || 'N/A'}</p>
            <p><span class="text-gray-500">OS:</span> ${escapeHtml(v.os) || 'N/A'}</p>
          </div>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Scores</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">Severity Score:</span> ${escapeHtml(v.severity_score) || 'N/A'}</p>
            <p><span class="text-gray-500">VPR Score:</span> ${escapeHtml(v.vpr_score) || 'N/A'}</p>
          </div>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Dates</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">First Seen:</span> ${v.first_seen ? escapeHtml(new Date(v.first_seen).toLocaleDateString()) : 'N/A'}</p>
            <p><span class="text-gray-500">Last Seen:</span> ${v.last_seen ? escapeHtml(new Date(v.last_seen).toLocaleDateString()) : 'N/A'}</p>
            <p><span class="text-gray-500">SLA Deadline:</span> ${v.sla_deadline ? escapeHtml(new Date(v.sla_deadline).toLocaleDateString()) : 'N/A'}</p>
            <p><span class="text-gray-500">Days Remaining:</span> <span class="${v.days_remaining < 0 ? 'text-red-600 font-bold' : ''}">${v.days_remaining !== null ? escapeHtml(v.days_remaining) : 'N/A'}</span></p>
          </div>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Status</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">Status:</span> <span class="px-2 py-1 bg-gray-100 rounded text-xs">${escapeHtml(v.status)}</span></p>
            <p><span class="text-gray-500">Resolved Date:</span> ${v.resolved_date ? escapeHtml(new Date(v.resolved_date).toLocaleDateString()) : 'N/A'}</p>
          </div>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Jira Integration</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">Ticket:</span> ${v.jira_ticket_url ? `<a href="${sanitizeUrl(v.jira_ticket_url)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline">${escapeHtml(v.jira_ticket_id)}</a>` : 'N/A'}</p>
            <p><span class="text-gray-500">Jira Status:</span> ${escapeHtml(v.jira_status) || 'N/A'}</p>
            <p><span class="text-gray-500">Assignee:</span> ${escapeHtml(v.jira_assignee) || 'N/A'}</p>
          </div>
        </div>

        ${v.status === 'accepted_risk' ? `
        <div class="col-span-2 bg-purple-50 p-4 rounded">
          <h4 class="font-semibold mb-2">Risk Acceptance</h4>
          <div class="space-y-1 text-sm">
            <p><span class="text-gray-500">EGRC Number:</span> <span class="font-mono">${escapeHtml(v.egrc_number) || 'N/A'}</span></p>
            <p><span class="text-gray-500">Expiry Date:</span> ${v.egrc_expiry_date ? escapeHtml(new Date(v.egrc_expiry_date).toLocaleDateString()) : 'N/A'}</p>
            <p><span class="text-gray-500">Accepted Date:</span> ${v.risk_accepted_date ? escapeHtml(new Date(v.risk_accepted_date).toLocaleDateString()) : 'N/A'}</p>
            <p><span class="text-gray-500">Reason:</span> ${escapeHtml(v.risk_accepted_reason) || 'N/A'}</p>
          </div>
        </div>
        ` : ''}

        ${v.solution ? `
        <div class="col-span-2 bg-green-50 p-4 rounded">
          <h4 class="font-semibold mb-2">Solution</h4>
          <p class="text-sm">${escapeHtml(v.solution)}</p>
        </div>
        ` : ''}

        ${v.remediation_guidance ? `
        <div class="col-span-2 bg-blue-50 p-4 rounded">
          <h4 class="font-semibold mb-2">AI Remediation Guidance</h4>
          <p class="text-sm whitespace-pre-wrap">${escapeHtml(v.remediation_guidance)}</p>
        </div>
        ` : ''}
      </div>
    `;
  } catch (err) {
    content.innerHTML = `<p class="text-red-600">Failed to load details: ${escapeHtml(err.message)}</p>`;
  }
}

// ==========================================
// Risk Accept Modal
// ==========================================

function openRiskModal(vulnId) {
  document.getElementById('risk-vuln-id').value = vulnId;
  document.getElementById('risk-modal').classList.remove('hidden');
  document.getElementById('risk-modal').classList.add('flex');
}

function closeRiskModal() {
  document.getElementById('risk-modal').classList.add('hidden');
  document.getElementById('risk-modal').classList.remove('flex');
  document.getElementById('risk-form').reset();
}

async function submitRiskAccept(event) {
  event.preventDefault();

  const vulnId = document.getElementById('risk-vuln-id').value;
  const egrcNumber = document.getElementById('risk-egrc-number').value;
  const expiryDate = document.getElementById('risk-expiry-date').value;
  const reason = document.getElementById('risk-reason').value;

  try {
    const url = `/api/vulnerabilities/${vulnId}/accept-risk?egrc_number=${encodeURIComponent(egrcNumber)}&egrc_expiry_date=${expiryDate}${reason ? `&reason=${encodeURIComponent(reason)}` : ''}`;
    const res = await fetch(url, { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to accept risk');
    }

    closeRiskModal();
    loadStats();
    loadVulnerabilities();
    loadAcceptedVulns();
    alert('Risk accepted successfully');
  } catch (err) {
    alert('Failed to accept risk: ' + err.message);
  }
}

// ==========================================
// Delete Vulnerability
// ==========================================

async function deleteVuln(vulnId) {
  if (!confirm('Are you sure you want to delete this vulnerability? This will also close the Jira ticket if one exists.')) {
    return;
  }

  try {
    const res = await fetch(`/api/vulnerabilities/${vulnId}`, { method: 'DELETE' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to delete');
    }

    const result = await res.json();
    loadStats();
    loadVulnerabilities();
    loadAcceptedVulns();
    loadApproachingSLA();

    if (result.jira_closed) {
      alert('Vulnerability deleted and Jira ticket closed');
    } else {
      alert('Vulnerability deleted');
    }
  } catch (err) {
    alert('Failed to delete: ' + err.message);
  }
}

// ==========================================
// Jira Sync
// ==========================================

async function syncJira(vulnId) {
  try {
    const res = await fetch(`/api/vulnerabilities/${vulnId}/sync-jira`, { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to sync');
    }

    loadVulnerabilities();
    loadAcceptedVulns();
    alert('Jira status synced');
  } catch (err) {
    alert('Failed to sync Jira: ' + err.message);
  }
}

async function syncAllJira() {
  try {
    const res = await fetch('/api/vulnerabilities/sync-all-jira', { method: 'POST' });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to sync');
    }

    const result = await res.json();
    loadVulnerabilities();
    loadAcceptedVulns();
    alert(result.message);
  } catch (err) {
    alert('Failed to sync all Jira: ' + err.message);
  }
}
