export function createBillingView({ api, esc, external, onSources, openConnection }) {
  const $ = s => document.querySelector(s);
  let active = false, report, generation = 0;
  const value = v => v === undefined || v === null ? 'Not returned' : String(v);
  function table(title, records, keys) { return `<section class="panel account-controls"><h3>${esc(title)}</h3>${records.length ? `<div class="table-wrap"><table class="account-table"><thead><tr>${keys.map(k => `<th>${esc(k)}</th>`).join('')}</tr></thead><tbody>${records.map(r => `<tr>${keys.map(k => `<td>${esc(value(r[k]))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : '<p>No records returned by the successful query in this scope/window.</p>'}</section>`; }
  function render() {
    $('#billing-export').disabled = !report;
    if (!report) { $('#billing-results').innerHTML = '<p>Check billing to query the current principal’s connected account/tenant contexts.</p>'; return; }
    let html = `<section class="panel account-controls"><h2>Billing coverage</h2><p>${esc(report.note)} Global completeness is not established.</p><p>Results preserve tenant, billing scope, window and currency. Overlapping scope totals are not added together.</p></section>`;
    for (const c of report.contexts) {
      html += `<section class="panel account-controls"><h2>${esc(c.account)} · ${esc(c.tenant)}</h2><p>Collection: ${esc(c.status)}</p></section>`;
      if (!c.report) continue;
      const r = c.report, s = r.sections;
      html += `<section class="panel account-controls"><p>${r.notes.map(esc).join(' ')}</p><p>${esc(r.range.from)} → ${esc(r.range.to)} UTC</p>${r.personalPortal ? external(r.personalPortal, 'Open personal order history', 'btn') : ''}</section>`;
      const types = { managementGroups: ['Accessible management groups', ['name', 'displayName']], resourceGroups: ['Resource-group fallback scopes', ['subscriptionId', 'name']], budgets: ['Authorized budgets', ['scope', 'name', 'amount', 'currentSpend', 'currency', 'grain', 'start', 'end']], m365Lifecycle: ['Microsoft subscription lifecycle (not invoice/payment data)', ['skuId', 'status', 'trial', 'licenses', 'nextLifecycle']], subscriptions: ['Accessible Azure subscriptions', ['name', 'id', 'tenant', 'state']], billingAccounts: ['Accessible billing accounts', ['displayName', 'name', 'agreement', 'status']], billingProfiles: ['Billing profiles', ['account', 'displayName', 'name', 'currency', 'status']], invoiceSections: ['Invoice sections', ['account', 'profile', 'displayName', 'state']], invoices: ['Invoice summaries', ['account', 'name', 'date', 'due', 'status', 'amount', 'currency']], billingProducts: ['Billing subscriptions/products', ['account', 'name', 'product', 'subscriptionId', 'status']], reservationOrders: ['Reservation orders', ['name', 'id', 'state', 'term', 'expiry']] };
      for (const [key, [title, fields]] of Object.entries(types)) if (s[key]) html += table(title, s[key], fields);
      if (s.costs) for (const cost of s.costs) html += table('Costs · ' + cost.scope, cost.rows, ['amount', 'currency']);
    }
    $('#billing-results').innerHTML = html;
    if (active) onSources(report.sources);
  }
  async function run() { const id = ++generation; $('#billing-run').disabled = true; $('#billing-status').textContent = 'Querying viewer-authorized billing scopes…'; try { const r = await api('/api/billing?days=' + encodeURIComponent($('#billing-days').value)); if (id !== generation) return; report = r; render(); $('#billing-status').textContent = r.partial ? 'Partial billing evidence; unavailable scopes and limits remain.' : 'Billing queries completed for connected contexts; global coverage remains unknown.'; } catch(e) { if (id === generation) $('#billing-status').textContent = e.message; } finally { if (id === generation) $('#billing-run').disabled = false; } }
  $('#billing-run').onclick = run; $('#billing-connect').onclick = openConnection;
  $('#billing-export').onclick = () => { const url = URL.createObjectURL(new Blob([JSON.stringify(report || {}, null, 2)], { type: 'application/json' })); const a = document.createElement('a'); a.href = url; a.download = 'Entity360-billing.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
  return { run, reset() { generation++; report = null; $('#billing-run').disabled = false; $('#billing-status').textContent = ''; render(); }, setActive(v) { active = v; if (active) { render(); onSources(report?.sources || []); } } };
}
