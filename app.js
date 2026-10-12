"use strict";

/*
 * Phishing Email Analyser
 *
 * Privacy model:
 * - No backend
 * - No external APIs
 * - No analytics
 * - No network requests
 * - Email content is processed locally in the browser
 */


/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const emailInput = document.getElementById("emailInput");
const analyseButton = document.getElementById("analyseButton");
const clearButton = document.getElementById("clearButton");
const characterCount = document.getElementById("characterCount");

const emptyState = document.getElementById("emptyState");
const resultsContent = document.getElementById("resultsContent");

const riskScore = document.getElementById("riskScore");
const riskClassification = document.getElementById("riskClassification");
const riskSummary = document.getElementById("riskSummary");

const scoreRing = document.getElementById("scoreRing");

const indicatorsList = document.getElementById("indicatorsList");
const indicatorCount = document.getElementById("indicatorCount");

const recommendationsList =
    document.getElementById("recommendationsList");


/* =========================================================
   EMAIL VALIDATIN
   =========================================================
*/

const MAX_EMAIL_LENGTH = 50000;

function validateEmailInput(value) {
    if (typeof value !== "string") {
        return {
            valid: false,
            message: "Email content must be text."
        };
    }

    if (value.length > MAX_EMAIL_LENGTH) {
        return {
            valid: false,
            message: "Email exceeds the 50,000-character limit."
        };
    }

    if (!value.trim()) {
        return {
            valid: false,
            message: "Please paste an email before analysis."
        };
    }

    return { valid: true, message: "" };
}


/* =========================================================
   SCORING CONFIGURATION
   =========================================================

   Each rule has:
   - id: unique identifier
   - name: user-facing name
   - points: score contribution
   - description: explanation shown to the user
   - detector: function that checks the email
*/


const RULES = [

    {
        id: "urgency",
        name: "Urgency or pressure language",
        points: 10,

        description:
            "The email uses pressure to encourage immediate action, " +
            "which can reduce the recipient's time to think or verify the request.",

        detector: detectUrgency
    },

    {
        id: "account_threat",
        name: "Account suspension or closure threat",
        points: 15,

        description:
            "The message threatens account suspension, closure, restriction " +
            "or loss of access unless the recipient acts.",

        detector: detectAccountThreat
    },

    {
        id: "password_request",
        name: "Password request",
        points: 20,

        description:
            "The email appears to request a password or other login credential.",

        detector: detectPasswordRequest
    },

    {
        id: "mfa_request",
        name: "MFA or verification-code request",
        points: 20,

        description:
            "The email requests a one-time password, MFA code, verification " +
            "code or similar authentication secret.",

        detector: detectMfaRequest
    },

    {
        id: "payment_request",
        name: "Payment or gift-card request",
        points: 15,

        description:
            "The message asks for payment, gift cards, vouchers, cryptocurrency " +
            "or another form of financial transfer.",

        detector: detectPaymentRequest
    },

    {
        id: "bank_change",
        name: "Bank-detail change request",
        points: 20,

        description:
            "The message requests that banking or payment details be changed.",

        detector: detectBankChange
    },

    {
        id: "credential_harvesting",
        name: "Credential-harvesting language",
        points: 20,

        description:
            "The email appears designed to persuade the recipient to enter " +
            "credentials or sensitive information into a verification page.",

        detector: detectCredentialHarvesting
    },

    {
        id: "shortened_url",
        name: "Shortened URL",
        points: 10,

        description:
            "A URL-shortening service is present. Shortened URLs hide the " +
            "final destination and make verification more difficult.",

        detector: detectShortenedUrls
    },

    {
        id: "raw_ip",
        name: "URL using a raw IP address",
        points: 15,

        description:
            "A URL uses an IP address instead of a conventional domain name.",

        detector: detectRawIpUrls
    },

    {
        id: "suspicious_url",
        name: "Suspicious URL structure",
        points: 15,

        description:
            "A URL contains characteristics commonly associated with suspicious " +
            "or deceptive links.",

        detector: detectSuspiciousUrls
    },

    {
        id: "misleading_link",
        name: "Potentially misleading link text",
        points: 15,

        description:
            "The visible link text does not appear to match its actual destination.",

        detector: detectMisleadingLinks
    },

    {
        id: "impersonation",
        name: "Impersonation language",
        points: 10,

        description:
            "The email uses language suggesting that the sender represents a " +
            "trusted organisation, department or authority.",

        detector: detectImpersonation
    },

    {
        id: "attachment",
        name: "Unusual or potentially dangerous attachment",
        points: 15,

        description:
            "The message references an attachment that may require additional scrutiny.",

        detector: detectAttachments
    },

    {
        id: "executable",
        name: "Executable attachment",
        points: 20,

        description:
            "The email references an executable file type that can directly run code.",

        detector: detectExecutableAttachments
    },

    {
        id: "macros",
        name: "Request to enable macros",
        points: 15,

        description:
            "The email asks the recipient to enable macros or similar active content.",

        detector: detectMacros
    },

    {
        id: "invoice",
        name: "Unexpected invoice language",
        points: 10,

        description:
            "The email contains invoice or payment language that may require independent verification.",

        detector: detectInvoiceLanguage
    },

    {
        id: "reply_to",
        name: "Sender and Reply-To mismatch",
        points: 15,

        description:
            "The From address and Reply-To address belong to different domains.",

        detector: detectReplyToMismatch
    },

    {
        id: "spf",
        name: "SPF authentication failure",
        points: 15,

        description:
            "The pasted authentication information reports an SPF failure.",

        detector: detectSpfFailure
    },

    {
        id: "dkim",
        name: "DKIM authentication failure",
        points: 15,

        description:
            "The pasted authentication information reports a DKIM failure.",

        detector: detectDkimFailure
    },

    {
        id: "dmarc",
        name: "DMARC authentication failure",
        points: 15,

        description:
            "The pasted authentication information reports a DMARC failure.",

        detector: detectDmarcFailure
    }

];


/* =========================================================
   REGEX / DETECTION PATTERNS
   ========================================================= */

const PATTERNS = {

    urgency: [
        /\burgent\b/i,
        /\bimmediately\b/i,
        /\bas soon as possible\b/i,
        /\baction required\b/i,
        /\bact now\b/i,
        /\bwithin\s+\d+\s*(hour|hours|minute|minutes)\b/i,
        /\blast warning\b/i,
        /\bfinal notice\b/i
    ],

    accountThreat: [
        /\bsuspend(ed|ion)?\b/i,
        /\baccount.{0,30}\b(close|closed|deactivat|disable|block|restrict)/i,
        /\baccess.{0,30}\b(revok|remove|lose|terminat)/i,
        /\baccount.{0,30}\bexpire/i
    ],

    password: [
        /\bpassword\b/i,
        /\blogin credentials?\b/i,
        /\benter.{0,30}password\b/i,
        /\bprovide.{0,30}password\b/i
    ],

    mfa: [
        /\bmfa\b/i,
        /\bone[- ]time (password|passcode)\b/i,
        /\botp\b/i,
        /\bverification code\b/i,
        /\bsecurity code\b/i,
        /\bauthentication code\b/i,
        /\b6[- ]digit code\b/i
    ],

    payment: [
        /\bgift card\b/i,
        /\bgift cards\b/i,
        /\bvoucher\b/i,
        /\bwire transfer\b/i,
        /\bpayment\b/i,
        /\bpay immediately\b/i,
        /\bbitcoin\b/i,
        /\bcryptocurrency\b/i,
        /\bprepaid card\b/i
    ],

    bankChange: [
        /\bchange.{0,40}(bank|banking).{0,40}(details|account|information)\b/i,
        /\bnew bank account\b/i,
        /\bupdated bank details\b/i,
        /\bnew banking details\b/i,
        /\bchange.{0,30}account number\b/i
    ],

    credentialHarvesting: [
        /\bverify.{0,50}(account|identity|credentials|password)\b/i,
        /\bconfirm.{0,50}(account|identity|credentials)\b/i,
        /\bsign in.{0,50}(verify|confirm|restore)\b/i,
        /\bvalidate.{0,50}(account|identity)\b/i,
        /\bsecurity verification\b/i
    ],

    impersonation: [
        /\bIT support\b/i,
        /\bsecurity team\b/i,
        /\bsecurity department\b/i,
        /\baccount team\b/i,
        /\bMicrosoft 365\b/i,
        /\bMicrosoft support\b/i,
        /\bfinance department\b/i,
        /\bCEO\b/i,
        /\bCFO\b/i,
        /\bexecutive office\b/i,
        /\bparcel service\b/i,
        /\bdelivery service\b/i
    ],

    macros: [
        /\benable macros?\b/i,
        /\bmacros? must be enabled\b/i,
        /\bclick.{0,30}enable content\b/i,
        /\benable content\b/i
    ],

    invoice: [
        /\binvoice\b/i,
        /\binvoice attached\b/i,
        /\boverdue invoice\b/i,
        /\bpayment due\b/i,
        /\boutstanding balance\b/i,
        /\bremittance\b/i
    ]

};


/* =========================================================
   HELPER FUNCTIONS
   ========================================================= */


function hasAnyPattern(text, patterns) {

    return patterns.some(pattern => pattern.test(text));

}



function extractUrls(text) {
    const urlPattern = /\bhttps?:\/\/[^\s<>"']+/gi;
    const matches = text.match(urlPattern) || [];

    // Limit the amount of URL processing performed per email.
    return matches.slice(0, 500).map(url =>
        url.replace(/[),.;!?]+$/, "")
    );
}


function parseSafeUrl(value) {
    if (typeof value !== "string" || value.length > 2048) {
        return null;
    }

    try {
        const parsed = new URL(value);

        if (
            parsed.protocol !== "http:" &&
            parsed.protocol !== "https:"
        ) {
            return null;
        }

        if (!parsed.hostname || parsed.username || parsed.password) {
            return null;
        }

        return parsed;
    } catch {
        return null;
    }
}


function extractEmailAddress(text, label) {

    const escapedLabel =
        label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const regex = new RegExp(
        escapedLabel +
        "\\s*:?\\s*[^<\\n]*<([^>]+)>|" +
        escapedLabel +
        "\\s*:?\\s*([A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,})",
        "i"
    );

    const match = text.match(regex);

    if (!match) {
        return null;
    }

    return (match[1] || match[2] || "").trim();

}


function getDomain(emailAddress) {

    if (!emailAddress || !emailAddress.includes("@")) {
        return null;
    }

    return emailAddress
        .split("@")
        .pop()
        .toLowerCase()
        .trim();

}


function normaliseDomain(domain) {

    return domain
        .replace(/^www\./, "")
        .toLowerCase();

}


/* =========================================================
   DETECTION FUNCTIONS
   ========================================================= */


function detectUrgency(text) {

    return hasAnyPattern(text, PATTERNS.urgency);

}


function detectAccountThreat(text) {

    return hasAnyPattern(text, PATTERNS.accountThreat);

}


function detectPasswordRequest(text) {

    return hasAnyPattern(text, PATTERNS.password);

}


function detectMfaRequest(text) {

    return hasAnyPattern(text, PATTERNS.mfa);

}


function detectPaymentRequest(text) {

    return hasAnyPattern(text, PATTERNS.payment);

}


function detectBankChange(text) {

    return hasAnyPattern(text, PATTERNS.bankChange);

}


function detectCredentialHarvesting(text) {

    return hasAnyPattern(text, PATTERNS.credentialHarvesting);

}



function detectShortenedUrls(text) {
    const urls = extractUrls(text);

    const shorteningDomains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "shorturl.at"
    ];

    return urls.some(url => {
        const parsed = parseSafeUrl(url);

        if (!parsed) {
            return false;
        }

        return shorteningDomains.includes(
            parsed.hostname.toLowerCase()
        );
    });
}



function detectRawIpUrls(text) {
    const urls = extractUrls(text);

    return urls.some(url => {
        const parsed = parseSafeUrl(url);

        if (!parsed) {
            return false;
        }

        return /^\d{1,3}(\.\d{1,3}){3}$/.test(
            parsed.hostname
        );
    });
}


function detectSuspiciousUrls(text) {
    const urls = extractUrls(text);

    const suspiciousTerms = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "confirm"
    ];

    const suspiciousTld = [
        ".zip",
        ".mov",
        ".click",
        ".top",
        ".xyz",
        ".work",
        ".support"
    ];

    return urls.some(url => {
        const parsed = parseSafeUrl(url);

        if (!parsed) {
            return false;
        }

        const hostname = parsed.hostname.toLowerCase();

        const manySubdomains =
            hostname.split(".").length >= 4;

        const hasSuspiciousTerm =
            suspiciousTerms.some(term =>
                hostname.includes(term)
            );

        const hasSuspiciousTld =
            suspiciousTld.some(tld =>
                hostname.endsWith(tld)
            );

        const encodedHost = hostname.includes("xn--");

        return (
            manySubdomains ||
            hasSuspiciousTerm ||
            hasSuspiciousTld ||
            encodedHost
        );
    });
}



function detectMisleadingLinks(text) {

    /*
     * Detect Markdown-style links:
     *
     * [Microsoft](https://example.test)
     */

    const markdownPattern =
        /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/gi;

    const matches = [...text.matchAll(markdownPattern)];

    return matches.some(match => {

        const visibleText =
            match[1].toLowerCase();

        const destination =
            match[2].toLowerCase();

        const words = [
            "microsoft",
            "office",
            "google",
            "paypal",
            "bank",
            "security",
            "login",
            "account"
        ];

        const claimsTrustedBrand =
            words.some(word =>
                visibleText.includes(word)
            );

        try {

            const hostname =
                new URL(destination).hostname;

            const visibleDomainMention =
                words.some(word =>
                    visibleText.includes(word)
                );

            const destinationContainsBrand =
                words.some(word =>
                    hostname.includes(word)
                );

            return (
                claimsTrustedBrand &&
                visibleDomainMention &&
                !destinationContainsBrand
            );

        } catch {

            return false;

        }

    });

}


function detectImpersonation(text) {

    return hasAnyPattern(text, PATTERNS.impersonation);

}



function detectAttachments(text) {
    const attachmentPattern =
        /\b[\w.-]+\.(pdf|doc|docx|xls|xlsx|xlsm|zip|rar|js|vbs|iso|img|html|htm)\b/i;

    return attachmentPattern.test(text);
}




function detectExecutableAttachments(text) {
    const executablePattern =
        /\b[\w.-]+\.(exe|scr|bat|cmd|com|msi|ps1|vbs|js|jar)\b/i;

    return executablePattern.test(text);
}



function detectMacros(text) {

    return hasAnyPattern(text, PATTERNS.macros);

}


function detectInvoiceLanguage(text) {

    return hasAnyPattern(text, PATTERNS.invoice);

}


function detectReplyToMismatch(text) {

    const from =
        extractEmailAddress(text, "From");

    const replyTo =
        extractEmailAddress(text, "Reply-To");

    if (!from || !replyTo) {
        return false;
    }

    const fromDomain =
        normaliseDomain(getDomain(from));

    const replyDomain =
        normaliseDomain(getDomain(replyTo));

    return (
        fromDomain &&
        replyDomain &&
        fromDomain !== replyDomain
    );

}


function detectSpfFailure(text) {

    return /\bspf\s*=\s*fail\b/i.test(text) ||
           /\bspf\b.{0,30}\bfail(ed|ure)?\b/i.test(text);

}


function detectDkimFailure(text) {

    return /\bdkim\s*=\s*fail\b/i.test(text) ||
           /\bdkim\b.{0,30}\bfail(ed|ure)?\b/i.test(text);

}


function detectDmarcFailure(text) {

    return /\bdmarc\s*=\s*fail\b/i.test(text) ||
           /\bdmarc\b.{0,30}\bfail(ed|ure)?\b/i.test(text);

}


/* =========================================================
   ANALYSIS ENGINE
   ========================================================= */


function analyseEmail(text) {

    const indicators = [];

    let score = 0;

    for (const rule of RULES) {

        let detected = false;

        try {

            detected = rule.detector(text);

        } catch (error) {

            console.error(
                `Detection error for ${rule.id}:`,
                error
            );

        }

        if (detected) {

            indicators.push(rule);

            score += rule.points;

        }

    }

    /*
     * The application deliberately caps the score at 100.
     *
     * This means the score represents accumulated warning signs,
     * rather than becoming a number larger than 100.
     */

    score = Math.min(score, 100);

    return {
        score,
        indicators
    };

}


/* =========================================================
   RISK CLASSIFICATION
   ========================================================= */


function classifyRisk(score) {

    if (score >= 60) {

        return {
            label: "High Risk",
            summary:
                "Multiple significant phishing or social-engineering " +
                "warning signs were detected.",
            className: "high"
        };

    }

    if (score >= 30) {

        return {
            label: "Suspicious",
            summary:
                "Several warning signs were detected. " +
                "The message should be independently verified.",
            className: "medium"
        };

    }

    return {
        label: "Low Risk",
        summary:
            "Few or no predefined warning signs were detected. " +
            "This does not prove that the email is safe.",
        className: "low"
    };

}


/* =========================================================
   RECOMMENDATIONS
   ========================================================= */


function buildRecommendations(indicators, score) {

    const recommendations = [];

    const ids =
        new Set(indicators.map(indicator => indicator.id));


    if (score >= 30) {

        recommendations.push(
            "Do not click links or open attachments in the message until it has been independently verified."
        );

    }


    if (
        ids.has("password_request") ||
        ids.has("mfa_request") ||
        ids.has("credential_harvesting")
    ) {

        recommendations.push(
            "Do not provide passwords, MFA codes or other authentication secrets in response to the email."
        );

    }


    if (
        ids.has("payment_request") ||
        ids.has("bank_change")
    ) {

        recommendations.push(
            "Verify financial requests using a known telephone number or an established internal process, not contact information contained in the email."
        );

    }


    if (
        ids.has("shortened_url") ||
        ids.has("raw_ip") ||
        ids.has("suspicious_url") ||
        ids.has("misleading_link")
    ) {

        recommendations.push(
            "Navigate to the organisation's official website or application manually instead of using the link in the email."
        );

    }


    if (
        ids.has("reply_to") ||
        ids.has("spf") ||
        ids.has("dkim") ||
        ids.has("dmarc")
    ) {

        recommendations.push(
            "Treat authentication or sender inconsistencies as reasons to verify the message through an independent channel."
        );

    }


    if (ids.has("executable") || ids.has("macros")) {

        recommendations.push(
            "Do not open the attachment or enable macros simply to investigate the email."
        );

    }


    recommendations.push(
        "Remember that this analyser identifies warning signs; it cannot definitively determine whether an email is malicious."
    );


    return recommendations;

}


/* =========================================================
   DISPLAY RESULTS
   ========================================================= */


function displayResults(result) {
    const classification = classifyRisk(result.score);

    riskScore.textContent = String(result.score);
    riskClassification.textContent = classification.label;
    riskSummary.textContent = classification.summary;

    indicatorCount.textContent =
        `${result.indicators.length} ${
            result.indicators.length === 1
                ? "indicator"
                : "indicators"
        }`;

    const colours = {
        high: "#ff7b86",
        medium: "#f5c766",
        low: "#66dda1"
    };

    const colour = colours[classification.className] || colours.low;

    scoreRing.style.borderColor = colour;
    riskClassification.style.color = colour;

    // Build the indicator list without interpreting strings as HTML.
    indicatorsList.replaceChildren();

    if (result.indicators.length === 0) {
        const card = document.createElement("div");
        card.className = "indicator";

        const title = document.createElement("strong");
        title.textContent = "No predefined warning signs detected";

        const description = document.createElement("p");
        description.textContent =
            "No configured indicators were detected. This does not " +
            "guarantee that the email is legitimate.";

        card.append(title, description);
        indicatorsList.appendChild(card);
    } else {
        for (const indicator of result.indicators) {
            const card = document.createElement("div");
            card.className = "indicator";

            const top = document.createElement("div");
            top.className = "indicator-top";

            const title = document.createElement("div");
            title.className = "indicator-title";

            const icon = document.createElement("span");
            icon.className = "indicator-icon";
            icon.textContent = "!";

            const name = document.createElement("span");
            name.textContent = indicator.name;

            title.append(icon, name);

            const points = document.createElement("span");
            points.className = "indicator-points";
            points.textContent = `+${indicator.points}`;

            top.append(title, points);

            const description = document.createElement("p");
            description.textContent = indicator.description;

            card.append(top, description);
            indicatorsList.appendChild(card);
        }
    }

    // Build recommendations as text, not HTML.
    recommendationsList.replaceChildren();

    const recommendations = buildRecommendations(
        result.indicators,
        result.score
    );

    for (const recommendation of recommendations) {
        const item = document.createElement("div");
        item.className = "recommendation";
        item.textContent = recommendation;

        recommendationsList.appendChild(item);
    }

    emptyState.classList.add("hidden");
    resultsContent.classList.remove("hidden");

    if (window.innerWidth < 900) {
        document.getElementById("resultsPanel")
            .scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
    }
}


/* =========================================================
   HTML ESCAPING
   =========================================================

   User-controlled email text should never be inserted
   into HTML without escaping.

   This prevents our own application from accidentally
   interpreting pasted content as HTML.
*/


function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


/* =========================================================
   USER INTERACTION
   ========================================================= */


function runAnalysis() {
    const text = emailInput.value;
    const validation = validateEmailInput(text);

    if (!validation.valid) {
        alert(validation.message);
        emailInput.focus();
        return;
    }

    try {
        const result = analyseEmail(text);
        displayResults(result);
    } catch {
        alert(
            "Analysis could not be completed. " +
            "Please try a smaller or different email."
        );
    }
}


function clearAnalysis() {

    emailInput.value = "";

    characterCount.textContent =
        "0 characters";

    resultsContent.classList.add("hidden");
    emptyState.classList.remove("hidden");

    emailInput.focus();

}


emailInput.addEventListener(
    "input",
    () => {

        characterCount.textContent =
            `${emailInput.value.length.toLocaleString()} characters`;

    }
);


analyseButton.addEventListener(
    "click",
    runAnalysis
);


clearButton.addEventListener(
    "click",
    clearAnalysis
);


/* =========================================================
   DEMONSTRATION EMAILS
   ========================================================= */


const DEMO_EMAILS = {

    obvious: `From: Security Team <security@secure-example.test>
Subject: URGENT - Your account will be suspended

URGENT ACTION REQUIRED.

Your account will be suspended within 24 hours.

Verify your account immediately by visiting:
https://secure-login.example.test/account

Please enter your password and the verification code sent to your phone.

Failure to complete verification will result in permanent account closure.`,


    sophisticated: `From: Corporate Services <operations@company-example.test>
Reply-To: verification@external-example.test
Subject: Action required: payroll profile verification

Good afternoon,

As part of a routine security review, several employee payroll profiles
require verification.

To prevent interruption to payroll processing, please confirm your
account information before the end of the business day.

You will be asked to sign in and confirm your credentials and
one-time verification code.

Please use the verification portal below:

[Corporate verification portal](https://account-review.example.test/verify)

Authentication-Results:
spf=fail
dkim=fail
dmarc=fail

Thank you,
Corporate Services`,


    microsoft: `From: Microsoft 365 Security <security@microsoft-example.test>
Subject: Your Microsoft 365 account requires verification

We detected unusual activity associated with your Microsoft 365 account.

Your account may be suspended if verification is not completed immediately.

Please sign in and verify your identity using the link below:

https://m365-security.example.test/login

You may be asked for your Microsoft 365 password and six-digit
verification code.

Failure to verify your account may result in loss of access.`,


    parcel: `From: Parcel Delivery <delivery@parcel-example.test>
Subject: Urgent: delivery payment required

Your parcel could not be delivered.

A small customs payment is required before delivery can continue.

Please make payment immediately using the secure payment portal:

https://delivery-payment.example.test/confirm

Your delivery will be cancelled if payment is not received today.

Do not reply to this email.`,


    invoice: `From: Finance Director <finance@example.test>
Subject: Urgent invoice payment

Hi,

I am currently in a meeting and need this invoice paid urgently.

Please process the outstanding payment today.

The supplier has changed their banking details, so use the new
bank account information in the attached document.

Attachment: Updated_Invoice.xlsm

Please enable macros if Microsoft Excel displays a security warning.

Regards,
Finance Director`,


    legitimate: `From: University Administration <admin@university-example.test>
Subject: Student services office hours

Dear Student,

Please note that the Student Services office will close at 15:00
on Friday due to scheduled staff training.

Normal operating hours will resume on Monday.

If you need assistance while the office is closed, please visit
the university's official website or contact Student Services using
the telephone number published on the university website.

Kind regards,

Student Services
University Administration`
};


/* =========================================================
   EXAMPLE BUTTONS
   ========================================================= */


document
    .querySelectorAll(".example-button")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                const exampleName =
                    button.dataset.example;

                emailInput.value =
                    DEMO_EMAILS[exampleName];

                characterCount.textContent =
                    `${emailInput.value.length.toLocaleString()} characters`;

                runAnalysis();

            }
        );

    });