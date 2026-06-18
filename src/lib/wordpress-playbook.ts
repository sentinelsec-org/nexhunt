/**
 * WordPress Attack Plan — turns wpscan findings into prioritized, actionable
 * next steps with a concrete command for each. Deterministic (no AI): each rule
 * maps a finding to the standard WordPress exploitation methodology.
 */
import type { WpVuln } from '@/stores/wordpress-store'

export type ActionPriority = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface WpAction {
  id: string
  priority: ActionPriority
  title: string
  why: string
  command?: string
  source: string
  inApp?: 'password-attack'   // action also wires an in-app control
}

export interface WpScanState {
  version: { value: string; status: string } | null
  theme: string | null
  plugins: string[]
  users: string[]
  vulns: WpVuln[]
  interesting: string[]
  configBackups: string[]
}

const PRIO_ORDER: Record<ActionPriority, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function vulnSearchTerm(title: string): string {
  return title
    .replace(/\s*[<>]=?\s*[\d.]+.*$/, '')   // drop "< 5.3.2 ..."
    .replace(/\s*-\s*.*$/, '')              // drop "- Unrestricted File Upload"
    .trim() || title
}

function interestingHas(items: string[], ...needles: string[]): string | null {
  const low = needles.map(n => n.toLowerCase())
  return items.find(t => low.some(n => t.toLowerCase().includes(n))) ?? null
}

export function buildAttackPlan(target: string, wp: WpScanState): WpAction[] {
  const url = target.startsWith('http') ? target.replace(/\/$/, '') : `https://${target}`
  const actions: WpAction[] = []

  // ── Config / DB backups — immediate, highest value ──
  wp.configBackups.forEach((u, i) => {
    actions.push({
      id: `backup-${i}`, priority: 'critical', source: u,
      title: 'Download exposed config / DB backup',
      why: 'An exposed wp-config or database dump almost always leaks DB credentials and the WordPress secret keys (full compromise).',
      command: `curl -sk "${u}" -o wp_backup_${i} && head -c 800 wp_backup_${i}`,
    })
  })

  // ── Vulnerabilities ──
  wp.vulns.forEach((v, i) => {
    const prio: ActionPriority = v.severity === 'high' ? 'critical' : v.severity === 'medium' ? 'high' : 'low'
    const term = vulnSearchTerm(v.title)
    actions.push({
      id: `vuln-${i}`, priority: prio, source: 'vulnerability',
      title: `Verify & exploit: ${v.title}`,
      why: 'WPScan matched this against its vuln DB. Confirm it is exploitable on this exact version before reporting — find a PoC and reproduce it.',
      command: `searchsploit ${JSON.stringify(term)}; echo '---'; nuclei -u "${url}" -tags wordpress,cve -severity ${v.severity},critical`,
    })
  })

  // ── Exposed debug log ──
  if (interestingHas(wp.interesting, 'debug log', 'debug.log')) {
    actions.push({
      id: 'debuglog', priority: 'high', source: 'debug.log exposed',
      title: 'Fetch wp-content/debug.log',
      why: 'WordPress debug logs frequently contain full paths, SQL errors, stack traces and sometimes tokens or credentials.',
      command: `curl -sk "${url}/wp-content/debug.log"`,
    })
  }

  // ── Users enumerated → password attack ──
  if (wp.users.length > 0) {
    const userList = wp.users.join(',')
    actions.push({
      id: 'password-attack', priority: 'high', source: `users: ${userList}`,
      title: `Password attack against ${wp.users.length} enumerated user(s)`,
      why: 'Valid usernames were enumerated. xmlrpc-multicall is the fastest attack (many passwords per request). Use an authorized wordlist and rate-limit on production.',
      command: `wpscan --url "${url}" --usernames ${userList} --passwords /usr/share/wordlists/rockyou.txt --password-attack xmlrpc-multicall --max-threads 5`,
      inApp: 'password-attack',
    })
  }

  // ── XML-RPC enabled ──
  if (interestingHas(wp.interesting, 'xml-rpc', 'xmlrpc')) {
    actions.push({
      id: 'xmlrpc', priority: 'medium', source: 'XML-RPC enabled',
      title: 'Abuse XML-RPC (method enum, SSRF pingback, brute amplification)',
      why: 'xmlrpc.php enables pingback-based SSRF and amplified brute-force (system.multicall). List methods first; if pingback.ping exists, test SSRF with a collaborator URL.',
      command: `curl -sk "${url}/xmlrpc.php" -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'`,
    })
  }

  // ── User registration enabled ──
  if (interestingHas(wp.interesting, 'registration')) {
    actions.push({
      id: 'registration', priority: 'medium', source: 'registration enabled',
      title: 'Register an account, then test authenticated surface',
      why: 'Open registration gives you a low-priv session. Re-run authenticated scans and look for privilege escalation in plugins.',
      command: `curl -sk "${url}/wp-login.php?action=register"`,
    })
  }

  // ── Directory listing / upload dir ──
  if (interestingHas(wp.interesting, 'directory listing', 'upload directory')) {
    actions.push({
      id: 'dirlist', priority: 'medium', source: 'directory listing',
      title: 'Browse the exposed upload/plugin directory',
      why: 'Directory listing on wp-content/uploads or plugins can reveal backups, exports, and unlinked sensitive files.',
      command: `curl -sk "${url}/wp-content/uploads/"`,
    })
  }

  // ── Outdated core ──
  if (wp.version && /insecure|out of date|outdated/i.test(wp.version.status)) {
    actions.push({
      id: 'core-version', priority: 'medium', source: `WordPress ${wp.version.value}`,
      title: `Map core ${wp.version.value} to public exploits`,
      why: 'The core version is flagged insecure. Check searchsploit and nuclei core templates for a matching public exploit.',
      command: `searchsploit wordpress ${wp.version.value}; echo '---'; nuclei -u "${url}" -tags wordpress -severity high,critical`,
    })
  }

  // ── Plugins: aggressive vuln enumeration ──
  if (wp.plugins.length > 0) {
    actions.push({
      id: 'plugins-deep', priority: 'medium', source: `${wp.plugins.length} plugin(s)`,
      title: 'Deep-scan every plugin for version + known vulns',
      why: 'Passive detection misses versions. Aggressive detection fingerprints exact plugin versions so the vuln DB can match CVEs.',
      command: `wpscan --url "${url}" --enumerate ap --plugins-detection aggressive --plugins-version-detection aggressive`,
    })
    // Per-plugin offline exploit search (collapsed into one command)
    actions.push({
      id: 'plugins-searchsploit', priority: 'low', source: 'plugins',
      title: 'Search offline exploit DB for each plugin',
      why: 'Quick offline triage of every identified plugin against Exploit-DB.',
      command: wp.plugins.map(p => `searchsploit ${JSON.stringify('wordpress ' + p)}`).join('; '),
    })
  }

  // ── readme / version disclosure ──
  if (interestingHas(wp.interesting, 'readme')) {
    actions.push({
      id: 'readme', priority: 'low', source: 'readme.html',
      title: 'Confirm version via readme.html',
      why: 'readme.html discloses the exact core version even when the generator meta tag is hidden.',
      command: `curl -sk "${url}/readme.html" | grep -i version`,
    })
  }

  // ── Baseline: always run nuclei WordPress templates ──
  actions.push({
    id: 'nuclei-baseline', priority: 'medium', source: 'baseline',
    title: 'Run the full nuclei WordPress/CMS template set',
    why: 'Covers misconfigurations, exposures and CVEs that wpscan does not, including REST API user leaks and known plugin RCEs.',
    command: `nuclei -u "${url}" -tags wordpress,cms -severity low,medium,high,critical`,
  })

  return actions.sort((a, b) => PRIO_ORDER[a.priority] - PRIO_ORDER[b.priority])
}
