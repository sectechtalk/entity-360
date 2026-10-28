// Investigate > Summary account card text. Pure so it can be tested; fmt formats an ISO time.
export function accountCardText(a, fmt = t => t) {
  if (!a) return { value: 'n/a', note: 'Account state not returned (needs User.Read.All)' };
  const value = a.enabled === true ? 'Enabled' : a.enabled === false ? 'Disabled' : 'Not returned';
  const parts = [a.userType || 'User type not returned', a.synced];
  parts.push(a.sessionsValidFrom ? `Sessions revoked/valid from ${fmt(a.sessionsValidFrom)}` : 'No session revocation recorded');
  if (a.lastSync) parts.push(`Last AD sync ${fmt(a.lastSync)}`);
  return { value, note: parts.filter(Boolean).join(' · ') };
}
