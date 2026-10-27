// Activity table = the Entra admin center Audit logs list view. Microsoft documents the default list as Date, Service,
// Category and Activity, Status; the blade also shows Initiated by (actor). Those 6 are the columns; the rest stays in the drawer.
export const ACTIVITY_HEADERS = ['Date', 'Service', 'Category', 'Activity', 'Status', 'Initiated by (actor)'];
const SERVICE_FALLBACK = { audit: 'Core Directory', azure: 'Azure Resource Manager', signin: 'Sign-in activity' };
export const activityService = (e, sources = []) => e.service || SERVICE_FALLBACK[e.source] || sources.find(s => s.id === e.source)?.short || e.source || 'n/a';
export const activityCategory = e => e.auditCategory || e.category || 'n/a';
export const activityStatus = e => e.result || 'n/a';
export const activityActor = e => e.actor || 'n/a';
export function activityColumns(sources = [], events = [], filterOptions) {
  const opt = get => (filterOptions ? filterOptions([], events.map(get)) : undefined);
  return [
    { key: 'act.service', label: 'Service', get: e => activityService(e, sources), options: opt(e => activityService(e, sources)) },
    { key: 'act.category', label: 'Category', get: activityCategory, options: opt(activityCategory) },
    { key: 'act.activity', label: 'Activity', get: e => e.title || 'n/a', options: opt(e => e.title || 'n/a') },
    { key: 'act.status', label: 'Status', get: activityStatus, options: opt(activityStatus) },
    { key: 'act.actor', label: 'Initiated by', header: 'Initiated by', get: activityActor, options: opt(activityActor) },
  ];
}
