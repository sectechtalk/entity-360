// AUTHENTICATION > MFA strength: every Entra MFA method ranked strongest to weakest, with what this tenant has
// (on in the Authentication methods policy, users registered, Conditional Access policies that accept it) and
// how to set up each method that is missing. Reads only what the other AUTHENTICATION pages already read:
// the Authentication methods policy, userRegistrationDetails, Conditional Access policies and authentication
// strengths. No new scope, nothing written. The setup steps are commands for an admin to run, never run here.
import { part } from '../bucket5.mjs';

const E = 'https://entra.microsoft.com/#view/';
const LEARN = 'https://learn.microsoft.com/entra/identity/authentication/';
export const LINKS = {
  methods: `${E}Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods`,
  ca: `${E}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`,
  securityInfo: 'https://mysignins.microsoft.com/security-info',
  intune: 'https://intune.microsoft.com/',
  strengths: `${LEARN}concept-authentication-strengths`,
};
// Passkey model IDs (AAGUIDs) for Microsoft Authenticator, from Microsoft Learn.
export const AUTHENTICATOR_AAGUIDS = ['90a3ccdf-635c-4729-a248-9b709135078f', 'de1e552d-db1d-4423-a619-566b625cdc84'];
// Built-in strengths as Microsoft Learn lists them; used when the strengths read fails, and for "Require MFA".
export const BUILT_IN = {
  phishingResistant: ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'],
  passwordless: ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor', 'deviceBasedPush'],
  mfa: ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor', 'deviceBasedPush', 'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse',
    'password,microsoftAuthenticatorPush', 'password,softwareOath', 'password,hardwareOath', 'password,sms', 'password,voice',
    'federatedMultiFactor', 'federatedSingleFactor,microsoftAuthenticatorPush', 'federatedSingleFactor,softwareOath', 'federatedSingleFactor,hardwareOath',
    'federatedSingleFactor,sms', 'federatedSingleFactor,voice'],
};
const MFA_STRENGTH_ID = '00000000-0000-0000-0000-000000000002';

const psHead = scope => `Import-Module Microsoft.Graph.Authentication\nConnect-MgGraph -Scopes ${scope} -NoWelcome`;
const patch = (id, body) => `${psHead('Policy.ReadWrite.AuthenticationMethod')}\n$body = @{\n${body}\n} | ConvertTo-Json -Depth 6\nInvoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/${id}' -Body $body -ContentType 'application/json'`;
const allUsers = (extra = '') => `  includeTargets = @(@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false${extra} })`;
const checkMethods = `${psHead('UserAuthenticationMethod.Read.All')}\n$me = (Get-MgContext).Account\n(Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$me/authentication/methods").value | ForEach-Object { $_.'@odata.type' -replace '#microsoft.graph.', '' }`;
const FIDO2_ON = patch('fido2', `  '@odata.type' = '#microsoft.graph.fido2AuthenticationMethodConfiguration'\n  state = 'enabled'\n  isSelfServiceRegistrationAllowed = $true\n${allUsers()}`);

// The ladder, strongest first. reg: methodsRegistered values that count a user as having it. combo: the
// authentication strength combination the method signs in with.
export const LADDER = [
  { id: 'fido2Key', name: 'FIDO2 hardware security key', pr: true, level: 'Phishing-resistant', combo: 'fido2', reg: ['fido2SecurityKey', 'passKeyDeviceBound'],
    guide: { why: 'The strongest method: the key never leaves the hardware, and attestation can limit which key models are allowed. Register two keys so one is a spare.',
      steps: ['Turn on Passkey (FIDO2) in the Authentication methods policy (command below, or Entra > Authentication methods > Policies > Passkey (FIDO2)).', 'Buy two FIDO2 security keys.', 'Each user signs in to Security info, chooses Add sign-in method > Passkey > Security key, and registers both keys.', 'Require it where it matters: a Conditional Access policy with the built-in Phishing-resistant MFA strength.'],
      code: FIDO2_ON, check: checkMethods, checkNote: 'fido2AuthenticationMethod appears in the list.', learn: `${LEARN}how-to-enable-passkey-fido2` } },
  { id: 'whfb', name: 'Windows Hello for Business', pr: true, level: 'Phishing-resistant', combo: 'windowsHelloForBusiness', reg: ['windowsHelloForBusiness', 'passKeyDeviceBoundWindowsHello'], policy: 'device',
    guide: { why: 'Phishing-resistant and passwordless on Windows. It is set per device in Windows or Intune, not in the Authentication methods policy, and it only counts when the user signed in with it.',
      steps: ['Intune admin center > Devices > Enrollment > Windows > Windows Hello for Business: set Configure Windows Hello for Business to Enabled (or deploy a Settings catalog policy for a group).', 'Sign in to a Microsoft Entra joined or hybrid joined Windows 10 or 11 device with a TPM. Windows asks the user to set up a PIN after MFA.', 'Check it on the device with the command below.'],
      code: 'dsregcmd /status | Select-String -Pattern "AzureAdJoined|NgcSet|AzureAdPrt"', codeNote: 'Run on the Windows device. NgcSet : YES means Windows Hello for Business is set up.', learn: 'https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/' } },
  { id: 'platformCredential', name: 'Platform Credential for macOS', pr: true, level: 'Phishing-resistant', combo: 'windowsHelloForBusiness', reg: ['macOsSecureEnclaveKey'], policy: 'device',
    guide: { why: 'The Mac version of Windows Hello for Business: a key in the Secure Enclave, phishing-resistant and passwordless. Set in Intune, not in the Authentication methods policy.',
      steps: ['Intune admin center > Devices > macOS > Configuration > Create > Settings catalog > Authentication > Extensible Single Sign On (SSO).', 'Set the Microsoft Enterprise SSO plug-in, Platform SSO with Authentication Method = Platform Credential, and assign to a group of Macs (macOS 14 or later).', 'On the Mac, Company Portal prompts the user to register. The key appears in the user\'s methods as a macOS Secure Enclave key.'],
      learn: `${LEARN}concept-authentication-platform-credential-for-macos` } },
  { id: 'cba', name: 'Certificate-based auth (smart card or certificate)', pr: 'multifactor', level: 'Phishing-resistant if multifactor', combo: 'x509CertificateMultiFactor', reg: [],
    guide: { why: 'Phishing-resistant only when the certificate is bound as multifactor (a smart card, or a certificate policy OID set to multifactor). Single-factor CBA satisfies no built-in strength. It needs a PKI, so it is the most work to run.',
      steps: ['Upload your root and issuing CA certificates first: Entra > Security > PKI-based trust store (or Certificate authorities). Without them sign-in fails.', 'Turn on Certificate-based authentication and set the default binding to multifactor (command below).', 'Map certificates to users (username binding, for example the UPN in the Subject Alternative Name).', 'Test with one user before widening the scope.'],
      code: patch('x509Certificate', `  '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'\n  state = 'enabled'\n  authenticationModeConfiguration = @{ x509CertificateAuthenticationDefaultMode = 'x509CertificateMultiFactor' }\n${allUsers()}`),
      learn: `${LEARN}how-to-certificate-based-authentication` } },
  { id: 'authenticatorPasskey', name: 'Passkey in Microsoft Authenticator', pr: true, level: 'Phishing-resistant', combo: 'fido2', reg: ['passKeyDeviceBoundAuthenticator'],
    guide: { why: 'A device-bound passkey on the phone: phishing-resistant and free. Cross-device sign-in needs Bluetooth near the computer.',
      steps: ['Turn on Passkey (FIDO2) (command below). If key restrictions are on with an allow list, add the Authenticator AAGUIDs 90a3ccdf-635c-4729-a248-9b709135078f (iOS) and de1e552d-db1d-4423-a619-566b625cdc84 (Android).', 'The user opens Security info > Add sign-in method > Passkey in Microsoft Authenticator, or adds it from the Authenticator app itself.'],
      code: FIDO2_ON, check: checkMethods, checkNote: 'fido2AuthenticationMethod appears, with a model of Microsoft Authenticator.', learn: `${LEARN}how-to-enable-authenticator-passkey` } },
  { id: 'syncedPasskey', name: 'Synced passkey (iCloud Keychain, Google Password Manager)', pr: true, level: 'Phishing-resistant', combo: 'fido2', reg: ['passKeySynced'],
    guide: { why: 'Phishing-resistant and survives losing a device, because it syncs through the Apple or Google account. No attestation, and admins cannot see which devices hold it.',
      steps: ['Turn on Passkey (FIDO2) with attestation not enforced, or a passkey profile that allows the Synced type (Entra > Authentication methods > Policies > Passkey (FIDO2) > Configure).', 'The user opens Security info > Add sign-in method > Passkey and saves it to iCloud Keychain or Google Password Manager.'],
      code: FIDO2_ON, learn: `${LEARN}how-to-authentication-passkeys-fido2` } },
  { id: 'phoneSignIn', name: 'Authenticator phone sign-in (passwordless approval)', pr: false, level: 'Passwordless', combo: 'deviceBasedPush', reg: ['microsoftAuthenticatorPasswordless'],
    guide: { why: 'Passwordless, so it meets the built-in Passwordless MFA strength, but it is still phishable. Use it as a step toward a passkey.',
      steps: ['Set Microsoft Authenticator to Enabled with Authentication mode Any (command below). The PATCH replaces the include list, so it targets all users.', 'In the Authenticator app the user opens the account and chooses Enable phone sign-in.'],
      code: patch('microsoftAuthenticator', `  '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration'\n  state = 'enabled'\n${allUsers("; authenticationMode = 'any'")}`),
      learn: `${LEARN}howto-authentication-passwordless-phone` } },
  { id: 'push', name: 'Password + Authenticator push (number matching)', pr: false, level: 'MFA', combo: 'password,microsoftAuthenticatorPush', reg: ['microsoftAuthenticatorPush'],
    guide: { why: 'The common default. Number matching is always on, which stops blind approvals, but a fake sign-in page can still relay the number.',
      steps: ['Set Microsoft Authenticator to Enabled with Authentication mode Any or Push (command below).', 'The user adds the account in Security info > Add sign-in method > Microsoft Authenticator.'],
      code: patch('microsoftAuthenticator', `  '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration'\n  state = 'enabled'\n${allUsers("; authenticationMode = 'any'")}`),
      learn: `${LEARN}concept-authentication-authenticator-app` } },
  { id: 'hardwareOath', name: 'Password + hardware OATH token', pr: false, level: 'MFA', combo: 'password,hardwareOath', reg: ['hardwareOneTimePasscode'],
    guide: { why: 'A code from a key fob for users who cannot use a phone. Phishable like any code.',
      steps: ['Buy OATH TOTP tokens (30 or 60 second, SHA-1) and get the seed file from the vendor.', 'Turn on Hardware OATH tokens in the Authentication methods policy.', 'Upload the tokens and assign each to a user (Entra > Authentication methods > Hardware OATH tokens), then the user activates it with a code.'],
      learn: `${LEARN}how-to-mfa-manage-oath-tokens` } },
  { id: 'totp', name: 'Password + Authenticator code (6-digit TOTP)', pr: false, level: 'MFA', combo: 'password,softwareOath', reg: ['softwareOneTimePasscode'],
    guide: { why: 'A code from an authenticator app. Works offline; phishable.',
      steps: ['Comes with Microsoft Authenticator. For other apps turn on Third-party software OATH tokens in the Authentication methods policy.', 'The user adds it in Security info > Add sign-in method > Authenticator app (or Other authenticator app).'],
      learn: `${LEARN}concept-authentication-oath-tokens` } },
  { id: 'sms', name: 'Password + SMS', pr: false, level: 'MFA', combo: 'password,sms', reg: ['mobilePhone', 'sms', 'alternateMobilePhone'], retire: true,
    guide: { why: 'Turn it off. SMS is open to SIM swap and number porting, and Microsoft-provided SMS retires February 1, 2027 (July 1, 2027 for Global Administrators and external users).',
      steps: ['Register a passkey (rows 1 to 6) for every user who has SMS. AUTHENTICATION > Registration lists their methods.', 'Then turn SMS off with the command below.'],
      code: patch('sms', `  '@odata.type' = '#microsoft.graph.smsAuthenticationMethodConfiguration'\n  state = 'disabled'`), learn: `${LEARN}concept-sms-voice-retirement` } },
  { id: 'voice', name: 'Password + voice call', pr: false, level: 'MFA', combo: 'password,voice', reg: ['mobilePhone', 'alternateMobilePhone', 'officePhone'], retire: true,
    guide: { why: 'Turn it off. Same risks and the same retirement dates as SMS.',
      steps: ['Register a passkey for every user who has a phone method, then turn voice off with the command below.'],
      code: patch('voice', `  '@odata.type' = '#microsoft.graph.voiceAuthenticationMethodConfiguration'\n  state = 'disabled'`), learn: `${LEARN}concept-sms-voice-retirement` } },
];

const cfgOf = (policy, id) => (policy?.authenticationMethodConfigurations || []).find(c => c.id === id);
const on = c => c?.state === 'enabled';
const modes = c => (c?.includeTargets || []).map(t => t.authenticationMode || 'any');

// Whether the tenant's Authentication methods policy allows the method. Returns { text, on } where on is
// true, false or null (not set in this policy).
export function methodState(row, policy) {
  if (!policy) return { text: 'Not read', on: null };
  if (row.policy === 'device') return { text: 'Set in Windows or Intune', on: null };
  const fido = cfgOf(policy, 'fido2'), ma = cfgOf(policy, 'microsoftAuthenticator');
  const kr = fido?.keyRestrictions;
  const allowList = kr?.isEnforcementEnabled && kr.enforcementType === 'allow' ? (kr.aaGuids || []).map(g => g.toLowerCase()) : null;
  switch (row.id) {
    case 'fido2Key': return on(fido) ? { text: fido.isAttestationEnforced ? 'On (attestation enforced)' : 'On', on: true } : { text: 'Off', on: false };
    case 'authenticatorPasskey':
      if (!on(fido)) return { text: 'Off', on: false };
      if (allowList && !AUTHENTICATOR_AAGUIDS.some(g => allowList.includes(g))) return { text: 'Blocked by key restrictions', on: false };
      return { text: 'On', on: true };
    case 'syncedPasskey':
      if (!on(fido)) return { text: 'Off', on: false };
      if (fido.isAttestationEnforced) return { text: 'Blocked (attestation enforced)', on: false };
      if (allowList) return { text: 'Only if its provider is on the allow list', on: null };
      return { text: 'On', on: true };
    case 'cba': {
      const c = cfgOf(policy, 'x509Certificate');
      if (!on(c)) return { text: 'Off', on: false };
      const multi = c.authenticationModeConfiguration?.x509CertificateAuthenticationDefaultMode === 'x509CertificateMultiFactor';
      return multi ? { text: 'On (multifactor)', on: true } : { text: 'On (single-factor: not MFA)', on: false };
    }
    case 'phoneSignIn': return on(ma) && modes(ma).some(m => m === 'any' || m === 'deviceBasedPush') ? { text: 'On', on: true } : { text: on(ma) ? 'Off (push only)' : 'Off', on: false };
    case 'push': return on(ma) && modes(ma).some(m => m === 'any' || m === 'push') ? { text: 'On', on: true } : { text: on(ma) ? 'Off (phone sign-in only)' : 'Off', on: false };
    case 'totp': {
      const sw = on(cfgOf(policy, 'softwareOath'));
      const app = on(ma) && ma.isSoftwareOathEnabled !== false;
      return sw || app ? { text: sw ? 'On' : 'On (in Authenticator)', on: true } : { text: 'Off', on: false };
    }
    default: {
      const c = cfgOf(policy, row.id);
      if (!c) return { text: 'Not returned', on: null };
      return on(c) ? { text: 'On', on: true } : { text: 'Off', on: false };
    }
  }
}

// Enabled Conditional Access policies that require MFA or an authentication strength, with the combinations
// each one accepts.
export function mfaPolicies(policies, strengths) {
  const byId = Object.fromEntries((strengths || []).map(s => [s.id, s.allowedCombinations || []]));
  const mfaCombos = byId[MFA_STRENGTH_ID] || BUILT_IN.mfa;
  return (policies || []).filter(p => p.state === 'enabled').map(p => {
    const g = p.grantControls || {};
    const s = g.authenticationStrength;
    const combos = s ? (s.allowedCombinations?.length ? s.allowedCombinations : byId[s.id] || []) : (g.builtInControls || []).includes('mfa') ? mfaCombos : null;
    return combos ? { name: p.displayName, combos } : null;
  }).filter(Boolean);
}

export function strengthRows(policy, users, policies) {
  return LADDER.map((row, i) => {
    const state = methodState(row, policy);
    const count = users ? users.filter(u => (u.methodsRegistered || []).some(m => row.reg.includes(m))).length : null;
    const accepted = policies.filter(p => p.combos.includes(row.combo)).length;
    return { row, rank: i + 1, state, count, accepted };
  });
}

// The weakest method that is on in the tenant and accepted by every MFA policy: an attacker picks the weakest
// method a user has, so this is the tenant's real floor unless a policy requires a stronger strength.
export function verdictFor(rows, policies) {
  const allowed = rows.filter(r => r.state.on === true && (r.row.reg.length === 0 || r.count !== 0));
  const floor = [...allowed].reverse().find(r => !policies.length || r.accepted === policies.length);
  if (!floor) return { status: 'Unknown', headline: 'Could not tell the weakest method in use.', detail: 'The Authentication methods policy or registration report did not return.' };
  const name = floor.row.name;
  const caText = policies.length ? `Every one of your ${policies.length} enabled MFA policies accepts it.` : 'No enabled Conditional Access policy requires MFA or an authentication strength.';
  if (floor.row.pr === true) return { status: 'OK', headline: `Weakest method allowed: ${name}. It is phishing-resistant.`, detail: caText };
  if (floor.row.retire) return { status: 'Needs attention', headline: `Weakest method allowed: ${name}.`, detail: `${caText} SMS and voice are open to SIM swap, and Microsoft-provided SMS and voice retire February 1, 2027.` };
  return { status: 'Warning', headline: `Weakest method allowed: ${name}. It is phishable.`, detail: `${caText} To raise the floor, require the Phishing-resistant MFA strength in Conditional Access for admins and sensitive apps.` };
}

const PR_TEXT = { true: 'Yes', false: 'No', multifactor: 'Only if multifactor' };
// Badge colour: on is good, except for SMS and voice where off is the good state.
const STATE_TONE = (row, s) => s.on === null ? 'info' : row.retire ? (s.on ? 'fail' : 'pass') : (s.on ? 'pass' : 'unknown');

async function strength(api, { notes, meta }) {
  const policy = await part(notes, 'Authentication methods policy', () => api.request('/v1.0/policies/authenticationMethodsPolicy'));
  const users = await part(notes, 'Registration report (needs the Reports Reader role or higher)', () => api.pages('/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999').then(r => r.rows));
  const ca = await part(notes, 'Conditional Access policies', () => api.pages('/v1.0/identity/conditionalAccess/policies').then(r => r.rows));
  const str = await part(notes, 'Authentication strengths', () => api.pages('/v1.0/policies/authenticationStrengthPolicies').then(r => r.rows));
  const pols = mfaPolicies(ca, str);
  const rows = strengthRows(policy, users, pols);
  if (policy && policy.policyMigrationState && policy.policyMigrationState !== 'migrationComplete') {
    notes.push(`Methods policy migration is "${policy.policyMigrationState}", so the legacy MFA and SSPR settings can still allow SMS, voice and codes. This page reads only the Authentication methods policy.`);
  }
  notes.push('Within the phishing-resistant rows, Conditional Access treats every method the same; the order there comes from NIST assurance level and device binding. Passkey profiles (preview) are not read; synced passkey status comes from the attestation setting.');
  const caCell = r => ca === null ? 'Not read' : pols.length ? `${r.accepted} of ${pols.length}` : 'No MFA policy';
  // Guides for what is missing: device-set methods nobody has registered, and policy methods that are off.
  // SMS and voice get a guide only when they are on (the advice is to move off them).
  const missing = rows.filter(r => r.row.policy === 'device' ? !r.count : r.row.retire ? r.state.on === true : r.state.on !== true);
  meta.verdict = verdictFor(rows, pols);
  return [
    { title: 'Methods ranked strongest to weakest', note: 'An attacker picks the weakest method a user has registered, so the weakest method that is on and accepted is the real strength.', link: LINKS.methods,
      columns: ['#', 'Method', 'Phishing-resistant', 'Strength level', 'In your tenant', 'Users registered', 'Accepted by your MFA policies'],
      rows: rows.map(r => [String(r.rank), r.row.name, PR_TEXT[r.row.pr], r.row.level, { badge: true, text: r.state.text, tone: STATE_TONE(r.row, r.state) },
        r.row.reg.length === 0 ? 'Not reported' : r.count === null ? 'Not read' : String(r.count), caCell(r)]) },
    { title: 'How to set up what you do not have', guides: missing.map(r => ({ title: `${r.rank}. ${r.row.name}`, status: r.state.text, ...r.row.guide })),
      note: missing.length ? 'Each command changes the tenant: run it yourself as an Authentication Policy Administrator after reading it. Entity 360 never runs it.' : 'Every method on the ladder is already on.' },
    pols.length ? { title: 'Your MFA policies and what they accept', link: LINKS.ca, columns: ['Policy', 'Weakest method it accepts that your tenant has on'],
      rows: pols.map(p => { const w = [...rows].reverse().find(r => r.state.on === true && p.combos.includes(r.row.combo)); return [p.name, w ? w.row.name : 'None of the methods that are on']; }) } : null,
  ];
}

export const STRENGTH_PAGES = {
  'a-strength': { section: 'AUTHENTICATION', title: 'MFA strength', load: strength },
};
