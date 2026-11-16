/**
 * Path Normalization, Query Parameter Extraction, and Data Masking
 */

/**
 * Normalizes dynamic URI path segments into parameter placeholders.
 * Example: /orders/123 -> /orders/{id}
 * Example: /products/42 -> /products/{id}
 * Example: /orders/ord_9981 -> /orders/{id}
 */
export function normalizePath(rawPath: string): string {
  if (!rawPath) return '/';

  // Strip query string and fragment
  const cleanPath = rawPath.split('?')[0].split('#')[0] || '/';

  // Split into segments
  const segments = cleanPath.split('/').filter(Boolean);
  if (segments.length === 0) return '/';

  const normalizedSegments = segments.map((seg, index) => {
    // 1. All-digit integer / numeric IDs (e.g., "123", "42")
    if (/^\d+$/.test(seg)) {
      return '{id}';
    }

    // 2. UUIDs (standard 8-4-4-4-12 hex)
    if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(seg)) {
      return '{id}';
    }

    // 3. Mongo / BSON Hex ObjectIDs (24 hex characters)
    if (/^[0-9a-fA-F]{24}$/.test(seg)) {
      return '{id}';
    }

    // 4. Prefixed resource IDs (e.g., ord_101, prod_881, usr_99, item_432)
    if (/^(ord|prod|usr|item|cart|tx|inv|req|user|order|product)_[a-zA-Z0-9_-]+$/i.test(seg)) {
      return '{id}';
    }

    // 5. If segment follows a known entity collection and isn't a known static sub-action
    const prevSeg = index > 0 ? segments[index - 1].toLowerCase() : '';
    const resourceCollections = ['products', 'orders', 'users', 'customers', 'items', 'categories', 'carts'];
    const reservedSubActions = ['search', 'new', 'all', 'summary', 'recent', 'export', 'count', 'bulk', 'checkout'];

    if (resourceCollections.includes(prevSeg) && !reservedSubActions.includes(seg.toLowerCase())) {
      // If it contains numbers or hyphens or alphanumeric tokens, treat as identifier
      if (/\d/.test(seg) || seg.length > 16 || seg.includes('-')) {
        return '{id}';
      }
    }

    return seg;
  });

  return '/' + normalizedSegments.join('/');
}

/**
 * Extracts ONLY query parameter names (keys), never their values.
 * Ensures that sensitive search queries, filter tokens, or credentials in URLs are never saved.
 */
export function extractQueryParamNames(urlOrQuery: string | Record<string, any>): string[] {
  if (!urlOrQuery) return [];

  if (typeof urlOrQuery === 'object') {
    return Object.keys(urlOrQuery);
  }

  try {
    const qIndex = urlOrQuery.indexOf('?');
    if (qIndex === -1) {
      if (urlOrQuery.startsWith('/') || !urlOrQuery.includes('=')) {
        return [];
      }
    }
    const queryString = qIndex !== -1 ? urlOrQuery.substring(qIndex + 1) : urlOrQuery;
    if (!queryString || queryString.trim() === '') return [];

    const params = new URLSearchParams(queryString);
    return Array.from(new Set(params.keys()));
  } catch {
    return [];
  }
}

/**
 * Determine login result based on request path and response status code.
 * ok: 2xx on /login
 * fail: 4xx or 5xx on /login
 * none: all non-login endpoints
 */
export function determineLoginResult(path: string, statusCode: number): 'ok' | 'fail' | 'none' {
  const lowerPath = path.toLowerCase();
  const isLoginEndpoint =
    lowerPath === '/login' ||
    lowerPath.endsWith('/login') ||
    lowerPath.includes('/login/') ||
    lowerPath.endsWith('/auth') ||
    lowerPath.includes('/authenticate');

  if (!isLoginEndpoint) {
    return 'none';
  }

  if (statusCode >= 200 && statusCode < 300) {
    return 'ok';
  }

  return 'fail';
}

/**
 * Sensitive key pattern for passwords, tokens, credentials, card numbers, OTPs, API keys.
 */
const SENSITIVE_KEY_REGEX =
  /(password|passwd|pass|secret|token|bearer|authorization|cookie|card|cvv|cvc|credit_card|otp|api_key|apikey|private_key|pin|ssn)/i;

/**
 * Mask sensitive data to prevent storing secrets or PII.
 */
export function maskSensitiveData(data: any): any {
  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    // Check for Bearer token string
    if (/^Bearer\s+.+$/i.test(data)) {
      return 'Bearer [MASKED]';
    }
    // Check for JWT token pattern
    if (/^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/.test(data) && data.length > 25) {
      return '[MASKED_TOKEN]';
    }
    // Check for Credit card pattern (13-19 digits with optional spaces/hyphens)
    if (/\b(?:\d{4}[-\s]?){3}\d{4}\b/.test(data)) {
      return data.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '****-****-****-****');
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(maskSensitiveData);
  }

  if (typeof data === 'object') {
    const sanitized: Record<string, any> = {};
    for (const [key, val] of Object.entries(data)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        sanitized[key] = '[MASKED]';
      } else {
        sanitized[key] = maskSensitiveData(val);
      }
    }
    return sanitized;
  }

  return data;
}

const RULE_ID_TO_ML_LABEL: Record<string, string> = {
  'RULE-01-BRUTE-FORCE': 'brute_force',
  'RULE-02-CRED-STUFFING': 'credential_stuffing',
  'RULE-03-RATE-LIMIT': 'rate_limit',
  'RULE-04-SCRAPING': 'scraping',
  'RULE-05-IDOR-BOLA': 'idor_bola',
  'RULE-06-SQL-INJECTION': 'sqli_suspected',
  'RULE-07-XSS': 'xss_suspected',
  'RULE-08-PATH-TRAVERSAL': 'path_traversal',
  'RULE-09-BAD-BOTS': 'bad_bot',
  'RULE-10-ADMIN-ACCESS': 'admin_probe',
  'RULE-11-ERROR-SPIKE': 'error_spike',
  'RULE-12-FAKE-SIGNUPS': 'fake_signups',
  'RULE-13-COUPON-ABUSE': 'coupon_abuse',
};

const RULE_NAME_TO_ML_LABEL: Record<string, string> = {
  'brute force login': 'brute_force',
  'credential stuffing': 'credential_stuffing',
  'rate limit exceeded': 'rate_limit',
  'e-commerce scraping': 'scraping',
  'idor / bola enumeration': 'idor_bola',
  'sql injection pattern': 'sqli_suspected',
  'cross-site scripting (xss)': 'xss_suspected',
  'path traversal & command injection': 'path_traversal',
  'malicious scanner / empty bot': 'bad_bot',
  'sensitive admin endpoint probe': 'admin_probe',
  'application error spike': 'error_spike',
  'spam account registration': 'fake_signups',
  'promo / coupon brute-forcing': 'coupon_abuse',
};

/**
 * Maps a rule ID or human-readable rule name to a canonical ML label (e.g. "sqli_suspected", "brute_force").
 */
export function ruleToLabel(ruleIdOrName?: string | null): string {
  if (!ruleIdOrName || ruleIdOrName.toLowerCase() === 'normal') return 'normal';
  if (RULE_ID_TO_ML_LABEL[ruleIdOrName]) {
    return RULE_ID_TO_ML_LABEL[ruleIdOrName];
  }
  const lower = ruleIdOrName.trim().toLowerCase();
  if (RULE_NAME_TO_ML_LABEL[lower]) {
    return RULE_NAME_TO_ML_LABEL[lower];
  }
  return lower
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'normal';
}

