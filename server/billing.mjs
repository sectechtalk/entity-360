import { GUID, fail } from './model.mjs';
const ARM = 'https://management.azure.com';
const source = (id, name) => ({ id, name, url: 'https://portal.azure.com/#view/Microsoft_Azure_Billing/BillingMenuBlade/~/overview' });
const namePart = value => typeof value === 'string' && /^[a-zA-Z0-9._:()-]{1,200}$/.test(value) ? encodeURIComponent(value) : null;
export function billingWindow(days = 30, now = Date.now()) {
  if (!Number.isInteger(days) || days < 1 || days > 90) throw fail('Choose a billing window from 1 to 90 days.');
  return { from: new Date(now - days * 86400000).toISOString(), to: new Date(now).toISOString() };
}
export function costRows(result) {
  const p = result.properties || {}, columns = (p.columns || []).map(c => c.name), rows = p.rows || [];
  return { rows: rows.slice(0, 100).map(row => ({ amount: row[columns.indexOf('PreTaxCost')] ?? row[columns.indexOf('Cost')] ?? null, currency: row[columns.indexOf('Currency')] ?? 'Not returned' })), partial: Boolean(p.nextLink) || rows.length > 100 };
}
export async function billingReport(api, { tenant, personal = false, azure = false, days = 30, now = Date.now() }) {
  const range = billingWindow(days, now);
  const r = { tenant, personal, range, sections: {}, sources: [], partial: false, updatedAt: new Date(now).toISOString(), complete: false, notes: ['Coverage is limited to successful authorized queries in the selected window. No currency or overlapping-scope totals are combined.', 'Personal purchase history, Microsoft 365 invoice PDFs/payment methods, CSP/Partner Center, GitHub, and Visual Studio billing are not queried by this release.'] };
  if (personal) { r.personalPortal = 'https://account.microsoft.com/billing/orders'; r.notes.push('Personal billing is available through the personal account portal; this dashboard has not retrieved its billing records.'); return r; }
  const run = async (id, meta, collect, consume = x => x) => {
    try { const data = await collect(); r.sources.push(meta); r.sections[id] = consume(data.rows ?? data); if (data.truncated) r.partial = true; return data.rows ?? data; }
    catch { r.partial = true; return null; }
  };
  await run('m365Lifecycle', { id: 'm365-lifecycle', name: 'Microsoft directory subscription lifecycle', url: 'https://admin.microsoft.com/' }, () => api.pages('/v1.0/directory/subscriptions'), rows => rows.map(s => ({ id: s.id, skuId: s.skuId, status: s.status, trial: s.isTrial, licenses: s.totalLicenses, nextLifecycle: s.nextLifecycleDateTime })));
  if (!azure) { r.notes.push('Connect Azure for this tenant to query ARM billing, subscriptions and costs.'); return r; }
  const subscriptions = await run('subscriptions', source('azure-subscriptions', 'Accessible Azure subscriptions'), () => api.pages('/subscriptions?api-version=2022-12-01', { origin: ARM }), rows => rows.map(s => ({ id: s.subscriptionId, name: s.displayName, tenant: s.tenantId, state: s.state })));
  await run('managementGroups', source('management-groups', 'Accessible Azure management groups'), () => api.pages('/providers/Microsoft.Management/managementGroups?api-version=2020-05-01', { origin: ARM }), rows => rows.map(g => ({ name: g.name, displayName: g.properties?.displayName || g.displayName })));
  const accounts = await run('billingAccounts', source('billing-accounts', 'Accessible billing accounts'), () => api.pages('/providers/Microsoft.Billing/billingAccounts?api-version=2024-04-01', { origin: ARM }), rows => rows.map(a => ({ name: a.name, displayName: a.properties?.displayName, agreement: a.properties?.agreementType, status: a.properties?.accountStatus })));
  await run('reservationOrders', source('reservations', 'Accessible reservation orders'), () => api.pages('/providers/Microsoft.Capacity/reservationOrders?api-version=2022-11-01', { origin: ARM }), rows => rows.map(o => ({ id: o.id, name: o.properties?.displayName || o.name, state: o.properties?.provisioningState, term: o.properties?.term, expiry: o.properties?.expiryDateTime })));
  const costs = [], invoices = [], profiles = [], invoiceSections = [], products = [], budgets = [], resourceGroups = [];
  let costQueries = 0;
  let budgetQueries = 0, budgetSucceeded = false, rgSucceeded = false;
  let costSucceeded = false, invoiceSucceeded = false, profileSucceeded = false, sectionsSucceeded = false, productsSucceeded = false;
  const cost = async scope => {
    if (++costQueries > 50) { r.partial = true; return false; }
    try {
      const data = await api.request(`${scope}/providers/Microsoft.CostManagement/query?api-version=2025-03-01`, { origin: ARM, method: 'POST', body: { type: 'Usage', timeframe: 'Custom', timePeriod: { from: range.from, to: range.to }, dataset: { granularity: 'None', aggregation: { totalCost: { name: 'PreTaxCost', function: 'Sum' } } } } });
      const normalized = costRows(data); costs.push({ scope, ...normalized }); costSucceeded = true; r.partial ||= normalized.partial; return true;
    } catch { r.partial = true; return false; }
  };
  const budget = async scope => {
    if (++budgetQueries > 50) { r.partial = true; return; }
    try { const result = await api.pages(`${scope}/providers/Microsoft.Consumption/budgets?api-version=2024-08-01`, { origin: ARM }); budgetSucceeded = true; r.partial ||= result.truncated; budgets.push(...result.rows.map(b => ({ scope, name: b.name, amount: b.properties?.amount, category: b.properties?.category, grain: b.properties?.timeGrain, currentSpend: b.properties?.currentSpend?.amount, currency: b.properties?.currentSpend?.unit, start: b.properties?.timePeriod?.startDate, end: b.properties?.timePeriod?.endDate }))); } catch { r.partial = true; }
  };
  const subscriptionRows = r.sections.subscriptions || [];
  if (subscriptionRows.length > 30 || (accounts || []).length > 20) r.partial = true;
  for (const s of subscriptionRows.slice(0, 30)) if (GUID.test(s.id)) {
    const scope = `/subscriptions/${s.id}`; const total = await cost(scope); await budget(scope);
    // When subscription-wide cost is denied, try visible resource-group scopes instead.
    if (!total) try {
      const result = await api.pages(`${scope}/resourcegroups?api-version=2021-04-01`, { origin: ARM }); rgSucceeded = true; r.partial ||= result.truncated;
      if (result.rows.length > 30) r.partial = true;
      for (const g of result.rows.slice(0, 30)) { const name = namePart(g.name); if (!name) { r.partial = true; continue; } const rg = `${scope}/resourceGroups/${name}`; resourceGroups.push({ subscriptionId: s.id, name: g.name }); await cost(rg); await budget(rg); }
    } catch { r.partial = true; }
  }
  if ((r.sections.managementGroups || []).length > 20) r.partial = true;
  for (const g of (r.sections.managementGroups || []).slice(0, 20)) { const name = namePart(g.name); if (name) await cost(`/providers/Microsoft.Management/managementGroups/${name}`); }
  for (const account of (accounts || []).slice(0, 20)) {
    const name = namePart(account.name); if (!name) { r.partial = true; continue; }
    const base = `/providers/Microsoft.Billing/billingAccounts/${name}`;
    await cost(base); await budget(base);
    try {
      const result = await api.pages(`${base}/invoices?api-version=2024-04-01&periodStartDate=${encodeURIComponent(range.from)}&periodEndDate=${encodeURIComponent(range.to)}`, { origin: ARM });
      invoices.push(...result.rows.map(i => ({ account: account.name, name: i.name, date: i.properties?.invoiceDate, due: i.properties?.dueDate, status: i.properties?.status, amount: i.properties?.totalAmount?.value, currency: i.properties?.totalAmount?.currency, periodStart: i.properties?.invoicePeriodStartDate, periodEnd: i.properties?.invoicePeriodEndDate }))); invoiceSucceeded = true; r.partial ||= result.truncated;
    } catch { r.partial = true; }
    try {
      const result = await api.pages(`${base}/billingSubscriptions?api-version=2024-04-01`, { origin: ARM });
      products.push(...result.rows.map(p => ({ account: account.name, name: p.properties?.displayName || p.name, status: p.properties?.status, product: p.properties?.productType, subscriptionId: p.properties?.subscriptionId }))); productsSucceeded = true; r.partial ||= result.truncated;
    } catch { r.partial = true; }
    try {
      const result = await api.pages(`${base}/billingProfiles?api-version=2024-04-01`, { origin: ARM });
      profileSucceeded = true; r.partial ||= result.truncated;
      if (result.rows.length > 20) r.partial = true;
      for (const p of result.rows.slice(0, 20)) {
        profiles.push({ account: account.name, name: p.name, displayName: p.properties?.displayName, status: p.properties?.status, currency: p.properties?.currency });
        const n = namePart(p.name); if (!n) { r.partial = true; continue; }
        const profileBase = `${base}/billingProfiles/${n}`; await cost(profileBase); await budget(profileBase);
        try {
          const result = await api.pages(`${profileBase}/invoices?api-version=2024-04-01&periodStartDate=${encodeURIComponent(range.from)}&periodEndDate=${encodeURIComponent(range.to)}`, { origin: ARM });
          invoiceSucceeded = true; r.partial ||= result.truncated;
          for (const i of result.rows) if (!invoices.some(existing => existing.account === account.name && existing.name === i.name)) invoices.push({ account: account.name, profile: p.name, name: i.name, date: i.properties?.invoiceDate, due: i.properties?.dueDate, status: i.properties?.status, amount: i.properties?.totalAmount?.value, currency: i.properties?.totalAmount?.currency, periodStart: i.properties?.invoicePeriodStartDate, periodEnd: i.properties?.invoicePeriodEndDate });
        } catch { r.partial = true; }
        try {
          const result = await api.pages(`${profileBase}/invoiceSections?api-version=2024-04-01`, { origin: ARM });
          sectionsSucceeded = true; r.partial ||= result.truncated;
          if (result.rows.length > 20) r.partial = true;
          for (const section of result.rows.slice(0, 20)) { invoiceSections.push({ account: account.name, profile: p.name, name: section.name, displayName: section.properties?.displayName, state: section.properties?.state }); const n = namePart(section.name); if (n) await cost(`${profileBase}/invoiceSections/${n}`); }
        } catch { r.partial = true; }
      }
    } catch { r.partial = true; }
  }
  for (const [key, ok, rows, label] of [['costs', costSucceeded, costs, 'Authorized scope costs'], ['invoices', invoiceSucceeded, invoices, 'Authorized invoice summaries'], ['billingProfiles', profileSucceeded, profiles, 'Authorized billing profiles'], ['invoiceSections', sectionsSucceeded, invoiceSections, 'Authorized invoice sections'], ['billingProducts', productsSucceeded, products, 'Authorized billing subscriptions/products']]) if (ok) { r.sections[key] = rows; r.sources.push(source(key, label)); }
  if (budgetSucceeded) { r.sections.budgets = budgets; r.sources.push(source('budgets', 'Authorized cost budgets')); }
  if (rgSucceeded) { r.sections.resourceGroups = resourceGroups; r.sources.push(source('resource-groups', 'Resource group scope fallback')); }
  r.notes.push('Collection limits: 30 subscriptions, 20 management groups, 30 resource groups per fallback subscription, 20 billing accounts, 20 profiles per account, 20 invoice sections per profile, 50 cost queries, 50 budget queries, and the configured API page limit. Exceeding a limit marks results partial.');
  return r;
}
export function demoBillingReport(profile) {
  return { tenant: 'Contoso · fictional', range: billingWindow(), sources: profile === 'reader' ? [] : [source('demo-billing', 'Demo subscription cost evidence')], sections: profile === 'reader' ? {} : { subscriptions: [{ id: '11111111-1111-1111-1111-111111111111', name: 'Demo Azure subscription', state: 'Enabled' }], costs: [{ scope: '/subscriptions/demo', rows: [{ amount: 42.50, currency: 'USD' }], partial: false }], invoices: [{ account: 'demo', name: 'DEMO-INV-001', date: 'Fictional', status: 'Paid', amount: 42.50, currency: 'USD' }] }, partial: profile === 'reader', complete: false, updatedAt: new Date().toISOString(), notes: ['Fictional demo. Scope summaries can overlap; do not add them together.'] };
}
