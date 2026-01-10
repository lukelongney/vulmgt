// Vulnerability Management Dashboard JS

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  loadEffectiveDate();
  loadStats();
  loadApproachingSLA();
  loadVulnerabilities();
  loadImports();
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
          <span class="px-2 py-1 rounded text-xs font-bold severity-${v.severity}">${v.severity.toUpperCase()}</span>
          <span class="ml-2 font-medium">${v.cve || 'No CVE'}</span>
          <span class="text-gray-500">on ${v.host}</span>
        </div>
        <div class="text-right">
          <span class="text-red-600 font-bold">${v.days_remaining} days left</span>
          ${v.jira_ticket_url ? `<a href="${v.jira_ticket_url}" target="_blank" class="ml-2 text-blue-600">${v.jira_ticket_id}</a>` : ''}
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
          </tr>
        </thead>
        <tbody>
          ${vulns.map(v => `
            <tr class="border-t hover:bg-gray-50">
              <td class="px-4 py-2">
                <span class="px-2 py-1 rounded text-xs font-bold severity-${v.severity}">${v.severity.toUpperCase()}</span>
              </td>
              <td class="px-4 py-2 font-mono text-sm">${v.cve || '-'}</td>
              <td class="px-4 py-2">${v.host}</td>
              <td class="px-4 py-2 max-w-xs truncate" title="${v.title}">${v.title}</td>
              <td class="px-4 py-2">
                <span class="px-2 py-1 bg-gray-100 rounded text-xs">${v.status}</span>
              </td>
              <td class="px-4 py-2 ${v.days_remaining < 0 ? 'text-red-600 font-bold' : v.days_remaining < 7 ? 'text-amber-600' : ''}">
                ${v.days_remaining !== null ? v.days_remaining + 'd' : '-'}
              </td>
              <td class="px-4 py-2">
                ${v.jira_ticket_url ? `<a href="${v.jira_ticket_url}" target="_blank" class="text-blue-600 hover:underline">${v.jira_ticket_id}</a>` : '-'}
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
              <td class="px-4 py-2">${new Date(i.imported_at).toLocaleString()}</td>
              <td class="px-4 py-2">${i.filename}</td>
              <td class="px-4 py-2 capitalize">${i.scanner}</td>
              <td class="px-4 py-2 text-green-600">+${i.new_count}</td>
              <td class="px-4 py-2">${i.existing_count}</td>
              <td class="px-4 py-2 text-blue-600">${i.resolved_count}</td>
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
      content.innerHTML = `<p class="text-red-600">${insights.error}</p>`;
      return;
    }

    let html = '';

    if (insights.patterns && insights.patterns.length > 0) {
      html += `
        <div class="mb-6">
          <h3 class="font-bold text-lg mb-2">Patterns Detected</h3>
          ${insights.patterns.map(p => `
            <div class="bg-gray-50 rounded p-3 mb-2">
              <div class="font-medium">${p.type.replace(/_/g, ' ').toUpperCase()}</div>
              <p>${p.description}</p>
              <p class="text-sm text-gray-600">Recommendation: ${p.recommendation}</p>
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
              <div class="font-medium">${t.topic}</div>
              <p class="text-sm">${t.reason} (${t.affected_count} affected)</p>
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
              <span>${a.action}</span>
              <span class="text-sm text-gray-600">${a.impact} | Effort: ${a.effort}</span>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (insights.raw_analysis) {
      html = `<pre class="bg-gray-50 p-4 rounded whitespace-pre-wrap">${insights.raw_analysis}</pre>`;
    }

    content.innerHTML = html || '<p class="text-gray-500">No insights available</p>';
  } catch (err) {
    content.innerHTML = `<p class="text-red-600">Failed to load insights: ${err.message}</p>`;
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
  } catch (err) {
    alert('Import failed: ' + err.message);
  }
}
