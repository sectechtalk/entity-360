// Per-device portal links for My device. Entra's device blade needs the device object id (and accepts the device id);
// Intune's needs the Intune managed-device id, found by matching azureADDeviceId to the Entra device id.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function entraDeviceLink(d) {
  if (!GUID.test(d?.id || '')) return null;
  return `https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DeviceDetailsMenuBlade/~/Properties/objectId/${d.id}${GUID.test(d.deviceId || '') ? `/deviceId/${d.deviceId}` : ''}`;
}
export function intuneDeviceLink(managedDeviceId) {
  return GUID.test(managedDeviceId || '') ? `https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${managedDeviceId}` : null;
}
// The Intune record for an Entra device, if this account's managed-device list contains it.
export const intuneMatch = (d, intune = []) => (intune || []).find(m => m.deviceId && d.deviceId && m.deviceId.toLowerCase() === d.deviceId.toLowerCase()) || null;

// PIM "My roles" activation pages (Microsoft's ActivationMenuBlade tabs). Only place in the app that links to activation.
export const PIM_ACTIVATION_LINKS = [
  ['Entra roles', 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles'],
  ['Azure resource roles', 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/azurerbac'],
  ['Groups', 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup'],
];

// Device trustType to the Entra portal's join type wording.
export function joinTypeLabel(trust) {
  return ({ AzureAd: 'Entra joined', ServerAd: 'Hybrid joined', Workplace: 'Registered' })[trust] || (trust ? trust : 'Join type not returned');
}
