import { ThreatRecord } from '../types/threats';

export interface ThreatReasoning {
  headline: string;
  whatHappened: string;
  whyFlagged: string;
  risk: string;
  falseAlarm: string;
  actions: string[];
  confidence: 'medium' | 'high';
}

const reasoningByRule: Record<string, Omit<ThreatReasoning, 'whatHappened' | 'whyFlagged'>> = {
  'RULE-01-BRUTE-FORCE': {
    headline: 'Someone is repeatedly guessing a login password',
    risk: 'If a guess works, the attacker takes over a customer account and can see orders or saved details.',
    falseAlarm: 'A real customer who forgot their password, or a shared office or school network.',
    actions: ['Block or rate-limit this IP', 'Check for a successful login afterwards', 'Add account lockout or CAPTCHA'],
    confidence: 'medium',
  },
  'RULE-02-CRED-STUFFING': {
    headline: 'Someone is trying stolen username and password lists',
    risk: 'Passwords leaked from other websites are being tried here. Any customer who reused a password could be hacked.',
    falseAlarm: 'Rare. A shared network where many people mistype passwords at once.',
    actions: ['Check which accounts were targeted', 'Block or rate-limit this IP', 'Turn on multi-factor authentication', 'Warn affected customers to reset passwords only if a login succeeded'],
    confidence: 'high',
  },
  'RULE-12-FAKE-SIGNUPS': {
    headline: 'Someone is creating accounts in bulk',
    risk: 'Fake accounts abuse promotions, spam your users and pollute your customer data.',
    falseAlarm: 'A school, office or event where many real people sign up from one network.',
    actions: ['Review the newly created accounts', 'Add CAPTCHA or email verification', 'Block this IP'],
    confidence: 'medium',
  },
  'RULE-03-RATE-LIMIT': {
    headline: 'One visitor is sending far too many requests',
    risk: 'Heavy traffic can slow your site for real customers and raise your hosting bill.',
    falseAlarm: 'A busy shared network, a partner integration, a monitoring tool, or your own load tests.',
    actions: ['Find out who owns this IP', 'Apply rate limiting and return 429', 'Block this IP'],
    confidence: 'medium',
  },
  'RULE-04-SCRAPING': {
    headline: 'A bot appears to be copying your product catalog',
    risk: 'Competitors can copy your prices and listings, and the extra load can slow the shop.',
    falseAlarm: 'Search engine crawlers, price comparison partners, or a customer opening many tabs.',
    actions: ['Check the User-Agent and IP owner', 'Rate-limit product pages', 'Add bot protection'],
    confidence: 'medium',
  },
  'RULE-13-COUPON-ABUSE': {
    headline: 'Someone is guessing promo codes',
    risk: 'A guessed code can give discounts you did not plan for, which costs you money.',
    falseAlarm: 'A customer trying a few codes from a newsletter or a friend.',
    actions: ['Check for redeemed codes from this IP', 'Limit coupon attempts per user and IP', 'Use longer random codes'],
    confidence: 'medium',
  },
  'RULE-05-IDOR-BOLA': {
    headline: 'Someone is trying other customers’ order or user numbers',
    risk: 'If your API does not check ownership, this person can read other customers’ orders and personal data.',
    falseAlarm: 'A support agent or admin tool that legitimately views many records.',
    actions: ['Check whether responses returned data or were blocked', 'Confirm ownership checks on every lookup', 'Block this IP'],
    confidence: 'high',
  },
  'RULE-06-SQL-INJECTION': {
    headline: 'Someone is trying to break into your database through a URL',
    risk: 'If the app is vulnerable, an attacker could read, change or delete data, including customer records.',
    falseAlarm: 'A shopper searching for text like “select union”, or a security test you started.',
    actions: ['Check whether the request got data back', 'Block this IP', 'Confirm queries are parameterized'],
    confidence: 'high',
  },
  'RULE-07-XSS': {
    headline: 'Someone is trying to inject a malicious script into your pages',
    risk: 'If your pages display this text unsafely, it can run in customers’ browsers and steal sessions or data.',
    falseAlarm: 'A developer or customer pasting HTML into a search or comment box.',
    actions: ['Check that user input is escaped', 'Add a Content-Security-Policy header', 'Block this IP'],
    confidence: 'high',
  },
  'RULE-08-PATH-TRAVERSAL': {
    headline: 'Someone is trying to read private files on your server',
    risk: 'A successful attack can expose configuration files, keys or even run commands on your server.',
    falseAlarm: 'Very rare. A broken link or a misconfigured client.',
    actions: ['Check the response status', 'Block this IP', 'Keep the server patched and files locked down'],
    confidence: 'high',
  },
  'RULE-10-ADMIN-ACCESS': {
    headline: 'Someone is looking for your admin or hidden pages',
    risk: 'Exposed admin panels or config files can give an attacker full control or your secret keys.',
    falseAlarm: 'Your own staff or developers opening admin tools from a new location.',
    actions: ['Check the response status', 'Restrict admin paths to your office or VPN', 'Block this IP'],
    confidence: 'high',
  },
  'RULE-09-BAD-BOTS': {
    headline: 'A hacking tool or an anonymous bot is visiting your API',
    risk: 'Scanners map your weak spots. An attack usually follows soon after.',
    falseAlarm: 'Your own security scans, uptime monitors, or simple scripts with no User-Agent.',
    actions: ['Confirm it is not your own scan', 'Block this IP', 'Watch it for follow-up threats'],
    confidence: 'medium',
  },
  'RULE-11-ERROR-SPIKE': {
    headline: 'Your app is suddenly returning lots of errors',
    risk: 'Customers may be failing to browse or check out. It can also mean an attack or a bad release.',
    falseAlarm: 'A recent deployment, a broken link, or a downstream outage.',
    actions: ['Check recent deployments and roll back if needed', 'Look at which endpoints fail', 'Look for a single noisy IP'],
    confidence: 'medium',
  },
};

export function getThreatReasoning(threat: ThreatRecord): ThreatReasoning {
  const base = reasoningByRule[threat.rule_id] ?? {
    headline: 'Suspicious activity was detected',
    risk: 'This activity may indicate abuse of your application.',
    falseAlarm: 'A legitimate integration, test, or unusual customer behavior.',
    actions: ['Review the request and response', 'Check the source IP', 'Apply the appropriate rate limit or block'],
    confidence: 'medium' as const,
  };

  return {
    ...base,
    whatHappened: `${threat.app_name} recorded ${threat.hit_count} matching request${threat.hit_count === 1 ? '' : 's'} from ${threat.client_ip}.`,
    whyFlagged: threat.evidence || `The request matched the ${threat.rule_name} detection rule.`,
  };
}
