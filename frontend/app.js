const form = document.querySelector('#verify-form');
const tokenInput = document.querySelector('#api-token');
const evidenceInput = document.querySelector('#evidence-id');
const message = document.querySelector('#form-message');
const result = document.querySelector('#result');
const button = form.querySelector('button');
const custody = document.querySelector('#custody');
const custodyForm = document.querySelector('#custody-form');
const custodyMessage = document.querySelector('#custody-message');
const custodyRows = document.querySelector('#custody-rows');
const anomalyForm = document.querySelector('#anomaly-form');
const anomalyMessage = document.querySelector('#anomaly-message');
const anomalyResult = document.querySelector('#anomaly-result');

const fields = {
  evidenceId: document.querySelector('#result-evidence-id'),
  filename: document.querySelector('#result-filename'),
  algorithm: document.querySelector('#result-algorithm'),
  original: document.querySelector('#result-original'),
  current: document.querySelector('#result-current'),
  date: document.querySelector('#result-date'),
  by: document.querySelector('#result-by'),
  status: document.querySelector('#result-status'),
  mark: document.querySelector('#result-mark'),
};

const savedToken = sessionStorage.getItem('cmrs_token');
if (savedToken) tokenInput.value = savedToken;

tokenInput.addEventListener('change', () => {
  sessionStorage.setItem('cmrs_token', tokenInput.value.trim());
});

function showMessage(text) {
  message.textContent = text;
}

function showResult(data) {
  const verified = data.match === true;
  result.hidden = false;
  result.className = `result ${verified ? 'verified' : 'violation'}`;
  fields.status.textContent = verified ? 'INTEGRITY VERIFIED' : 'INTEGRITY VIOLATION';
  fields.mark.textContent = verified ? '\u2713' : '\u26a0';
  fields.evidenceId.textContent = data.evidence_id;
  fields.filename.textContent = data.filename;
  fields.algorithm.textContent = data.algorithm;
  fields.original.textContent = data.original_hash;
  fields.current.textContent = data.current_hash;
  fields.date.textContent = new Date(data.verified_at).toLocaleString();
  fields.by.textContent = data.verified_by;
  custody.hidden = false;
  loadCustody(data.evidence_id, tokenInput.value.trim()).catch((error) => {
    custodyMessage.textContent = error.message;
  });
}

function renderCustody(events) {
  custodyRows.replaceChildren();
  for (const event of events) {
    const row = document.createElement('tr');
    [
      new Date(event.transferred_at).toLocaleString(),
      event.status,
      event.released_by || 'Evidence created',
      event.received_by,
      event.location || 'Not recorded',
      event.authenticated_user,
    ].forEach((value) => {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    });
    custodyRows.append(row);
  }
}

async function loadCustody(evidenceId, token) {
  const response = await fetch(`/api/evidence/${encodeURIComponent(evidenceId)}/custody`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Custody history could not be loaded.');
  renderCustody(data);
}

custodyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  custodyMessage.textContent = '';
  const evidenceId = fields.evidenceId.textContent;
  const token = tokenInput.value.trim();
  try {
    const response = await fetch(`/api/evidence/${encodeURIComponent(evidenceId)}/custody`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        received_by_id: document.querySelector('#received-by-id').value.trim(),
        action: document.querySelector('#custody-action').value,
        comments: document.querySelector('#custody-comments').value.trim() || null,
        location: document.querySelector('#custody-location').value.trim() || null,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Custody event could not be recorded.');
    custodyForm.reset();
    custodyMessage.textContent = 'Custody event recorded.';
    await loadCustody(evidenceId, token);
  } catch (error) {
    custodyMessage.textContent = error.message;
  }
});

anomalyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  anomalyMessage.textContent = '';
  anomalyResult.hidden = true;
  const userId = document.querySelector('#analysis-user-id').value.trim();
  const token = tokenInput.value.trim();
  if (!userId || !token) {
    anomalyMessage.textContent = 'Enter an admin token and user ID.';
    return;
  }
  try {
    const response = await fetch(`/api/admin/anomaly/users/${encodeURIComponent(userId)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Analysis could not be completed.');
    anomalyResult.hidden = false;
    document.querySelector('#anomaly-label').textContent = data.label;
    document.querySelector('#anomaly-score').textContent = data.score === null ? 'Insufficient data' : `Score: ${data.score.toFixed(4)}`;
    document.querySelector('#anomaly-explanation').textContent = data.explanation;
  } catch (error) {
    anomalyMessage.textContent = error.message;
  }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showMessage('');
  result.hidden = true;

  const token = tokenInput.value.trim();
  const evidenceId = evidenceInput.value.trim();
  if (!token || !evidenceId) {
    showMessage('Enter a bearer token and evidence ID.');
    return;
  }

  sessionStorage.setItem('cmrs_token', token);
  button.disabled = true;
  button.textContent = 'Verifying...';
  try {
    const response = await fetch(`/api/evidence/verify/${encodeURIComponent(evidenceId)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || 'Verification could not be completed.');
    }
    showResult(data);
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Verify integrity';
  }
});
// ---- Security Alerts (Stage 18) ----
const alertsLoad = document.querySelector('#alerts-load');
const alertsFilter = document.querySelector('#alerts-status-filter');
const alertsMessage = document.querySelector('#alerts-message');
const alertsEmpty = document.querySelector('#alerts-empty');
const alertsList = document.querySelector('#alerts-list');

const SEVERITY_LABELS = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
const STATUS_LABELS = { open: 'Open', reviewed: 'Reviewed', resolved: 'Resolved', dismissed: 'Dismissed' };

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

function badgeClass(value, prefix) {
  return `${prefix} ${prefix}-${String(value ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
}

function relatedLabel(alert) {
  const parts = [];
  if (alert.case_id) parts.push(`case ${alert.case_id}`);
  if (alert.evidence_id) parts.push(`evidence ${alert.evidence_id}`);
  if (alert.user_id) parts.push(`user ${alert.user_id}`);
  return parts.join(' · ') || '—';
}

async function loadAlerts() {
  const token = tokenInput.value.trim();
  if (!token) {
    alertsMessage.textContent = 'Enter an admin bearer token to load alerts.';
    return;
  }
  alertsMessage.textContent = 'Loading alerts…';
  alertsEmpty.hidden = true;
  alertsList.hidden = true;
  alertsLoad.disabled = true;
  const status = alertsFilter.value;
  try {
    const url = `/api/admin/alerts${status ? `?status=${encodeURIComponent(status)}` : ''}`;
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Alerts could not be loaded.');
    renderAlerts(data);
  } catch (error) {
    alertsMessage.textContent = error.message;
  } finally {
    alertsLoad.disabled = false;
  }
}

function renderAlerts(alerts) {
  if (alerts.length === 0) {
    alertsMessage.textContent = '';
    alertsEmpty.hidden = false;
    alertsList.hidden = true;
    return;
  }
  alertsMessage.textContent = `${alerts.length} alert(s) shown.`;
  alertsEmpty.hidden = true;
  alertsList.hidden = false;
  alertsList.replaceChildren();

  for (const alert of alerts) {
    const card = document.createElement('article');
    card.className = 'alert-card';

    const head = document.createElement('div');
    head.className = 'alert-header';
    const title = document.createElement('strong');
    title.textContent = alert.alert_type.replace(/_/g, ' ');
    title.className = 'alert-title';
    const badges = document.createElement('div');
    badges.className = 'alert-badges';
    const sev = document.createElement('span');
    sev.className = badgeClass(alert.severity, 'sev');
    sev.textContent = SEVERITY_LABELS[alert.severity] || alert.severity;
    const st = document.createElement('span');
    st.className = badgeClass(alert.status, 'st');
    st.textContent = STATUS_LABELS[alert.status] || alert.status;
    badges.append(sev, st);
    head.append(title, badges);
    card.append(head);

    const when = document.createElement('p');
    when.className = 'alert-when';
    when.textContent = `${new Date(alert.created_at).toLocaleString()}  ·  related: ${relatedLabel(alert)}`;
    card.append(when);

    const desc = document.createElement('p');
    desc.className = 'alert-desc';
    desc.textContent = alert.explanation;
    card.append(desc);

    const meta = document.createElement('p');
    meta.className = 'alert-meta';
    meta.textContent = alert.reviewed_by
      ? `Reviewed by ${alert.reviewed_by}${alert.reviewed_at ? ' on ' + new Date(alert.reviewed_at).toLocaleString() : ''}`
      : 'Not yet reviewed';
    if (alert.resolution) meta.textContent += ` — Resolution: ${alert.resolution}`;
    card.append(meta);

    if (alert.status === 'open' || alert.status === 'reviewed') {
      const form = document.createElement('form');
      form.className = 'alert-review';
      form.dataset.alertId = alert.id;

      const sel = document.createElement('select');
      sel.innerHTML = [
        ['reviewed', 'Reviewed'],
        ['resolved', 'Resolved'],
        ['dismissed', 'Dismissed'],
      ].map(([v, l]) => `<option value="${v}">${l}</option>`).join('');

      const res = document.createElement('input');
      res.type = 'text';
      res.placeholder = 'Resolution / remarks (optional)';
      res.maxLength = 2000;

      const btn = document.createElement('button');
      btn.type = 'submit';
      btn.textContent = 'Review alert';

      form.append(sel, res, btn);
      const msg = document.createElement('p');
      msg.className = 'form-message';
      form.append(msg);
      form.addEventListener('submit', (e) => reviewAlert(e, form, msg));
      card.append(form);
    }

    alertsList.append(card);
  }
}

async function reviewAlert(event, form, msg) {
  event.preventDefault();
  const token = tokenInput.value.trim();
  const statusValue = form.querySelector('select').value;
  const resolution = form.querySelector('input').value.trim() || null;
  msg.textContent = '';
  try {
    const response = await fetch(`/api/admin/alerts/${form.dataset.alertId}/review`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: statusValue, resolution }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Alert could not be reviewed.');
    msg.textContent = `Alert marked ${statusValue}.`;
    await loadAlerts();
  } catch (error) {
    msg.textContent = error.message;
  }
}

alertsLoad.addEventListener('click', loadAlerts);
alertsFilter.addEventListener('change', loadAlerts);

