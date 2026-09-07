function detectAttack(req) {
    const url = decodeURIComponent(req.originalUrl || "");
    const body = JSON.stringify(req.body || {});
    const headers = JSON.stringify(req.headers || {});

    const input = `${url} ${body} ${headers}`.toLowerCase();

    // SQL Injection patterns
    const sqlPatterns = [
        /(\bor\b|\band\b)\s+[\w'"]+\s*=\s*[\w'"]+/i,
        /union\s+select/i,
        /select\s+.*\s+from/i,
        /drop\s+table/i,
        /--/,
        /'\s*or\s*'1'\s*=\s*'1/i
    ];

    // XSS patterns
    const xssPatterns = [
        /<script/i,
        /javascript:/i,
        /onerror\s*=/i,
        /onload\s*=/i,
        /<iframe/i
    ];

    // Path Traversal
    const pathTraversalPatterns = [
        /\.\.\//,
        /\.\.\\/,
        /etc\/passwd/i,
        /windows\\system32/i
    ];

    if (sqlPatterns.some(pattern => pattern.test(input))) {
        return {
            malicious: true,
            attackType: "SQL Injection",
            severity: "HIGH"
        };
    }

    if (xssPatterns.some(pattern => pattern.test(input))) {
        return {
            malicious: true,
            attackType: "Cross-Site Scripting",
            severity: "HIGH"
        };
    }

    if (pathTraversalPatterns.some(pattern => pattern.test(input))) {
        return {
            malicious: true,
            attackType: "Path Traversal",
            severity: "HIGH"
        };
    }

    return {
        malicious: false,
        attackType: "None",
        severity: "LOW"
    };
}

module.exports = detectAttack;