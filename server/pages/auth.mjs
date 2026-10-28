// AUTHENTICATION section: Methods policy, Registration, Conditional Access inventory.
import { part, yesNo, day } from '../bucket5.mjs';
const E = 'https://entra.microsoft.com/#view/';
const NAMES = { microsoftAuthenticator: 'Microsoft Authenticator', fido2: 'Passkey (FIDO2)', sms: 'SMS', voice: 'Voice call', email: 'Email OTP', temporaryAccessPass: 'Temporary Access Pass', softwareOath: 'Software OATH tokens', hardwareOath: 'Hardware OATH tokens', x509Certificate: 'Certificate-based auth', qrCodePin: 'QR code' };

async function methods(api, { notes }) {
  const p = await api.request('/v1.0/policies/authenticationMethodsPolicy');
  const camp = p.registrationEnforcement?.authenticationMethodsRegistrationCampaign;
  const targets = c => (c.includeTargets || []).map(t => t.id === 'all_users' ? 'All users' : `${t.targetType || 'group'} ${t.id}`).join(', ') || 'None';
  return [
    { title: 'Authentication methods', link: `${E}Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods`, columns: ['Method', 'State', 'Included', 'Excluded'],
      rows: (p.authenticationMethodConfigurations || []).map(c => [NAMES[c.id] || c.id, c.state === 'enabled' ? 'Enabled' : 'Disabled', targets(c), (c.excludeTargets || []).map(t => t.id).join(', ') || 'None']) },
    { title: 'Policy settings', columns: ['Setting', 'Value'], rows: [
      ['Policy migration state', p.policyMigrationState || 'Not returned'], ['Reconfirm methods every (days)', String(p.reconfirmationInDays ?? 'Not returned')],
      ['Registration campaign (nudge)', camp ? `${camp.state}, snooze ${camp.snoozeDurationInDays} days` : 'Not returned'],
      ['System-preferred MFA', p.systemCredentialPreferences?.state || 'Not returned'], ['Last modified', day(p.lastModifiedDateTime)],
    ] },
  ];
}

async function registration(api, { notes }) {
  const rows = (await api.pages('/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999')).rows;
  const count = f => String(rows.filter(f).length);
  return [
    { title: 'Summary', columns: ['Measure', 'Users'], rows: [['Users in report', String(rows.length)], ['MFA capable', count(r => r.isMfaCapable)], ['MFA registered', count(r => r.isMfaRegistered)], ['Passwordless capable', count(r => r.isPasswordlessCapable)], ['SSPR registered', count(r => r.isSsprRegistered)], ['SSPR capable', count(r => r.isSsprCapable)], ['Admins without MFA', count(r => r.isAdmin && !r.isMfaRegistered)]] },
    { title: 'Users not registered for MFA', note: 'Admins first.', link: `${E}Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails`, columns: ['User', 'Admin', 'Methods', 'SSPR registered', 'Updated'],
      rows: rows.filter(r => !r.isMfaRegistered).sort((a, b) => (b.isAdmin === true) - (a.isAdmin === true)).slice(0, 200).map(r => [r.userPrincipalName, yesNo(r.isAdmin), (r.methodsRegistered || []).join(', ') || 'None', yesNo(r.isSsprRegistered), day(r.lastUpdatedDateTime)]) },
  ];
}

async function ca(api, { notes }) {
  const pol = (await api.pages('/v1.0/identity/conditionalAccess/policies')).rows;
  const loc = await part(notes, 'Named locations', () => api.pages('/v1.0/identity/conditionalAccess/namedLocations').then(r => r.rows));
  const ctx = await part(notes, 'Authentication contexts', () => api.pages('/v1.0/identity/conditionalAccess/authenticationContextClassReferences').then(r => r.rows));
  const str = await part(notes, 'Authentication strengths', () => api.pages('/v1.0/policies/authenticationStrengthPolicies').then(r => r.rows));
  const STATE = { enabled: 'On', disabled: 'Off', enabledForReportingButNotEnforced: 'Report-only' };
  const users = u => [u?.includeUsers?.join(', '), u?.includeGroups?.length && `${u.includeGroups.length} groups`, u?.includeRoles?.length && `${u.includeRoles.length} roles`].filter(Boolean).join('; ') || 'None';
  const grant = p => [...(p.grantControls?.builtInControls || []), p.grantControls?.authenticationStrength?.displayName].filter(Boolean).join(` ${p.grantControls?.operator || ''} `) || (p.sessionControls ? 'Session controls' : 'None');
  return [
    { title: 'Policies', note: `${pol.length} policies: ${pol.filter(p => p.state === 'enabled').length} on, ${pol.filter(p => p.state === 'enabledForReportingButNotEnforced').length} report-only, ${pol.filter(p => p.state === 'disabled').length} off.`, link: `${E}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`,
      columns: ['Policy', 'State', 'Users', 'Excluded', 'Apps', 'Grant', 'Modified'],
      rows: pol.map(p => { const u = p.conditions?.users || {}; return [p.displayName, STATE[p.state] || p.state, users(u), String((u.excludeUsers?.length || 0) + (u.excludeGroups?.length || 0)), (p.conditions?.applications?.includeApplications || []).join(', ') || 'None', grant(p), day(p.modifiedDateTime || p.createdDateTime)]; }) },
    loc && { title: 'Named locations', columns: ['Location', 'Type', 'Trusted', 'Detail'], rows: loc.map(l => l.ipRanges ? [l.displayName, 'IP ranges', yesNo(l.isTrusted), l.ipRanges.map(r => r.cidrAddress).join(', ')] : [l.displayName, 'Countries', 'No', (l.countriesAndRegions || []).join(', ')]) },
    ctx && { title: 'Authentication contexts', columns: ['ID', 'Name', 'Published'], rows: ctx.map(c => [c.id, c.displayName, yesNo(c.isAvailable)]) },
    str && { title: 'Authentication strengths', columns: ['Strength', 'Type', 'Combinations'], rows: str.map(s => [s.displayName, s.policyType === 'builtIn' ? 'Built-in' : 'Custom', (s.allowedCombinations || []).join(', ')]) },
  ];
}

export const AUTH_PAGES = {
  'a-methods': { section: 'AUTHENTICATION', title: 'Methods policy', load: methods },
  'a-registration': { section: 'AUTHENTICATION', title: 'Registration', load: registration },
  'a-ca': { section: 'AUTHENTICATION', title: 'Conditional Access', load: ca },
};
