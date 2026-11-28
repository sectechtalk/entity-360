// Single-entity PDF report: one button on the Summary (people, apps, managed identities) and on a device's page.
// The server reads every source at click time and returns a PDF, so the button shows progress and any error.
export function reportUrl(entity, range) {
  if (!entity) return '';
  if (entity.type === 'device') {
    const q = new URLSearchParams({ type: 'device' });
    if (entity.entraId) q.set('entraId', entity.entraId);
    if (entity.intuneId) q.set('intuneId', entity.intuneId);
    return `/api/investigate/report.pdf?${q}`;
  }
  return `/api/investigate/report.pdf?${new URLSearchParams({ id: entity.id, type: entity.type, from: range?.from || '', to: range?.to || '' })}`;
}
export const REPORT_LABEL = 'PDF report';
export const REPORT_BUSY = 'Building PDF…';
export const REPORT_TIP = 'Download everything Entity 360 can read about this entity as one PDF. It reads every source again, so it can take a minute.';

// Fetch the PDF and save it. Resolves to a message for the toast; throws with the server's error text.
export async function downloadReport(url, { headers = {}, fetcher = fetch, doc = document } = {}) {
  const response = await fetcher(url, { headers });
  if (!response.ok) {
    let message = 'The PDF report could not be built.';
    try { const data = await response.json(); if (data?.error) message = data.error; } catch { /* not JSON */ }
    throw new Error(message);
  }
  const blob = await response.blob();
  const name = /filename="([^"]+)"/.exec(response.headers.get('content-disposition') || '')?.[1] || 'entity-360-report.pdf';
  const href = URL.createObjectURL(blob), a = doc.createElement('a');
  a.href = href; a.download = name; doc.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 2000);
  return `Downloaded ${name}`;
}

// Wire a button: busy state while the server works, toast with the outcome.
export function bindReportButton(button, { url, headers, toast }) {
  if (!button) return;
  button.onclick = async () => {
    if (button.disabled) return;
    const label = button.textContent;
    button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = REPORT_BUSY;
    try { toast(await downloadReport(url(), { headers: headers() })); }
    catch (e) { toast(e.message); }
    finally { button.disabled = false; button.removeAttribute('aria-busy'); button.textContent = label; }
  };
}
