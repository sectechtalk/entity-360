// Deployment / onboarding log: renders public/deployment-log.json (identifiers only, no secrets).
// Claude appends a step to that file after each onboarding action; this view only reads it.
export function createDeploymentView({ esc }) {
  let log = null, machine = 'all';
  const $ = selector => document.querySelector(selector);
  function render() {
    if (!log) return;
    const names = log.machines.map(m => m.name);
    const steps = log.steps
      .filter(s => machine === 'all' || s.machines.includes(machine))
      .sort((a, b) => a.time.localeCompare(b.time) || a.id - b.id);
    const deviations = steps.filter(s => s.deviation).length;
    $('#deployment-content').innerHTML = `
      <section class="panel account-controls"><h2>${esc(log.title)}</h2><p>${esc(log.note)}</p>
        <div class="account-actions"><label>Machine <select id="deployment-machine"><option value="all">All machines</option>${names.map(n => `<option value="${esc(n)}" ${n === machine ? 'selected' : ''}>${esc(n)}</option>`).join('')}</select></label>
        <span class="muted">${steps.length} steps · ${deviations} with deviations</span></div></section>
      <section class="panel account-card"><div class="panel-heading"><h2>Current status</h2></div><div class="table-wrap"><table class="account-table"><thead><tr><th>Machine</th><th>Windows</th>${log.status.columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>
        ${log.machines.filter(m => machine === 'all' || m.name === machine).map(m => `<tr><th>${esc(m.name)}<small>${esc(m.role)}</small></th><td>${esc(m.os)}</td>${(log.status.rows[m.name] || []).map(v => `<td>${esc(v)}</td>`).join('')}</tr>`).join('')}
      </tbody></table></div></section>
      <section class="panel account-card"><div class="panel-heading"><h2>Steps</h2><p>Deviation = where this machine needed something different from the others.</p></div><div class="table-wrap"><table class="account-table deployment-steps"><thead><tr><th>#</th><th>Time (UTC)</th><th>Phase</th><th>Machines</th><th>By</th><th>What was done</th><th>Result</th><th>Deviation</th></tr></thead><tbody>
        ${steps.map(s => `<tr class="${s.deviation ? 'has-deviation' : ''}"><td>${s.id}</td><td>${esc(s.time)}</td><td>${esc(s.phase)}</td><td>${s.machines.map(esc).join(', ')}</td><td>${esc(s.by)}</td><td>${esc(s.action)}</td><td>${esc(s.result)}</td><td>${esc(s.deviation || '')}</td></tr>`).join('')}
      </tbody></table></div></section>
      ${(log.commands || []).length ? `<section class="panel account-card"><div class="panel-heading"><h2>Troubleshooting commands</h2><p>Read-only unless 'Changes' says otherwise. Copy and run where shown.</p></div><div class="table-wrap"><table class="account-table deployment-ref"><thead><tr><th>Check</th><th>Run on</th><th>Changes</th><th>Command</th><th>Good result</th></tr></thead><tbody>
        ${log.commands.map(c => `<tr><td>${esc(c.name)}</td><td>${esc(c.runOn)}</td><td>${esc(c.changes)}</td><td><code class="deployment-command">${esc(c.command)}</code></td><td>${esc(c.good)}</td></tr>`).join('')}
      </tbody></table></div></section>` : ''}
      ${(log.troubleshooting || []).length ? `<section class="panel account-card"><div class="panel-heading"><h2>Failures seen and fixes</h2><p>Every error hit during this deployment, its cause and the fix. Step numbers refer to the Steps table.</p></div><div class="table-wrap"><table class="account-table deployment-ref"><thead><tr><th>Symptom / error text</th><th>Where</th><th>Cause</th><th>Fix</th><th>Steps</th></tr></thead><tbody>
        ${log.troubleshooting.map(f => `<tr><td><code class="deployment-command">${esc(f.symptom)}</code></td><td>${esc(f.where)}</td><td>${esc(f.cause)}</td><td>${esc(f.fix)}</td><td>${f.steps.join(', ')}</td></tr>`).join('')}
      </tbody></table></div></section>` : ''}`;
    $('#deployment-machine').onchange = event => { machine = event.target.value; render(); };
  }
  async function load() {
    try {
      const response = await fetch('/deployment-log.json', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      log = await response.json();
      render();
    } catch (error) { $('#deployment-content').innerHTML = `<section class="panel account-controls"><p>Could not load the deployment log: ${esc(error.message)}</p></section>`; }
  }
  // Loaded once when first opened; Refresh reloads it. Switching views does not refetch.
  return { setActive(value) { if (value && !log) load(); }, refresh: load };
}
