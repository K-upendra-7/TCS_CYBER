/**
 * passwordSimilarity.js - Personal-Detail Similarity and Pattern Analysis
 * 
 * Compares password strings against user-provided personal data using:
 * - Direct substring matching (case-insensitive)
 * - Reversed token matching
 * - Leetspeak substitution mapping (@->a, 4->a, 3->e, 1/!->i, 0->o, $/5->s, 7->t)
 * - Combinations / concatenations (e.g., Name + Year or Name + Symbol + Number)
 * - Levenshtein fuzzy edit distance for close variations
 */

/**
 * Normalizes a string by converting common leetspeak characters to standard letters.
 * @param {string} str - Raw string
 * @returns {string}
 */
export function normalizeLeetspeak(str) {
    if (!str || typeof str !== "string") return "";
    return str
        .toLowerCase()
        .replace(/[@4]/g, "a")
        .replace(/3/g, "e")
        .replace(/[1!|]/g, "i")
        .replace(/0/g, "o")
        .replace(/[$5]/g, "s")
        .replace(/7/g, "t")
        .replace(/8/g, "b");
}

/**
 * Strips all non-alphanumeric characters for clean string comparison.
 * @param {string} str
 * @returns {string}
 */
export function stripSpecial(str) {
    if (!str || typeof str !== "string") return "";
    return str.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

/**
 * Calculates the Levenshtein edit distance between two strings.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function calculateLevenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    let previous = Array.from({ length: b.length + 1 }, (_, i) => i);

    for (let i = 1; i <= a.length; i++) {
        const current = [i];
        for (let j = 1; j <= b.length; j++) {
            const insertion = current[j - 1] + 1;
            const deletion = previous[j] + 1;
            const replacement = previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1);
            current.push(Math.min(insertion, deletion, replacement));
        }
        previous = current;
    }

    return previous[b.length];
}

/**
 * Reverses a string.
 * @param {string} str
 * @returns {string}
 */
function reverseString(str) {
    return str.split("").reverse().join("");
}

/**
 * @typedef {Object} SimilarityMatch
 * @property {string} category - Type of personal info matched
 * @property {string} label - Human-friendly label
 * @property {string} matchType - 'exact' | 'substring' | 'reversed' | 'leetspeak' | 'fuzzy' | 'combination'
 * @property {string} description - Clear explanation of the detected similarity
 * @property {number} severity - 0 to 100 risk score
 */

/**
 * Analyzes similarity between a password and an array of personal tokens.
 * @param {string} password - The password to analyze
 * @param {Array<import('./userData.js').PersonalToken>} tokens - Processed personal tokens
 * @returns {{
 *   similarityScore: number,
 *   matches: SimilarityMatch[],
 *   hasHighSimilarity: boolean,
 *   explanations: string[]
 * }}
 */
export function analyzePasswordSimilarity(password, tokens = []) {
    if (!password || !tokens.length) {
        return {
            similarityScore: 0,
            matches: [],
            hasHighSimilarity: false,
            explanations: []
        };
    }

    const passLower = password.toLowerCase();
    const passStripped = stripSpecial(passLower);
    const passLeetspeak = normalizeLeetspeak(passLower);
    const passLeetspeakStripped = stripSpecial(passLeetspeak);

    const matches = [];
    const explanations = [];
    let totalSeverity = 0;

    tokens.forEach(token => {
        const tokVal = token.value;
        const tokStripped = stripSpecial(tokVal);
        const tokReversed = reverseString(tokVal);
        const tokReversedStripped = reverseString(tokStripped);

        // 1. EXACT MATCH
        if (passLower === tokVal || passStripped === tokStripped) {
            const severity = Math.round(100 * token.weight);
            matches.push({
                category: token.category,
                label: token.label,
                matchType: "exact",
                description: `Password is identical to your ${token.label.toLowerCase()} ("${token.originalCase}").`,
                severity
            });
            explanations.push(`Directly matches your ${token.label.toLowerCase()} ("${token.originalCase}").`);
            totalSeverity = Math.max(totalSeverity, severity);
            return;
        }

        // 2. SUBSTRING MATCH (Direct containment)
        if (tokVal.length >= 3 && passLower.includes(tokVal)) {
            const ratio = tokVal.length / password.length;
            const severity = Math.round(Math.min(95, 60 + ratio * 35) * token.weight);
            matches.push({
                category: token.category,
                label: token.label,
                matchType: "substring",
                description: `Contains your ${token.label.toLowerCase()} ("${token.originalCase}") as a substring.`,
                severity
            });
            explanations.push(`Contains your ${token.label.toLowerCase()} ("${token.originalCase}").`);
            totalSeverity = Math.max(totalSeverity, severity);
            return;
        }

        // 3. LEETSPEAK / SUBSTITUTION MATCH
        if (tokStripped.length >= 3 && (passLeetspeak.includes(tokStripped) || passLeetspeakStripped.includes(tokStripped))) {
            const severity = Math.round(85 * token.weight);
            matches.push({
                category: token.category,
                label: token.label,
                matchType: "leetspeak",
                description: `Contains a leetspeak/symbol substitution of your ${token.label.toLowerCase()} ("${token.originalCase}").`,
                severity
            });
            explanations.push(`Uses symbol substitutions for your ${token.label.toLowerCase()} ("${token.originalCase}").`);
            totalSeverity = Math.max(totalSeverity, severity);
            return;
        }

        // 4. REVERSED MATCH
        if (tokVal.length >= 3 && (passLower.includes(tokReversed) || passStripped.includes(tokReversedStripped))) {
            const severity = Math.round(75 * token.weight);
            matches.push({
                category: token.category,
                label: token.label,
                matchType: "reversed",
                description: `Contains your ${token.label.toLowerCase()} spelled backwards ("${tokReversed}").`,
                severity
            });
            explanations.push(`Contains your reversed ${token.label.toLowerCase()} ("${tokReversed}").`);
            totalSeverity = Math.max(totalSeverity, severity);
            return;
        }

        // 5. FUZZY / EDIT DISTANCE MATCH (for words with length >= 5)
        if (tokVal.length >= 5 && passStripped.length >= 4) {
            const dist = calculateLevenshtein(passStripped, tokStripped);
            const maxLen = Math.max(passStripped.length, tokStripped.length);
            const similarity = 1 - (dist / maxLen);

            if (similarity >= 0.75 && dist <= 2) {
                const severity = Math.round(70 * token.weight);
                matches.push({
                    category: token.category,
                    label: token.label,
                    matchType: "fuzzy",
                    description: `Closely resembles your ${token.label.toLowerCase()} ("${token.originalCase}") with minor variation.`,
                    severity
                });
                explanations.push(`Closely resembles your ${token.label.toLowerCase()} ("${token.originalCase}").`);
                totalSeverity = Math.max(totalSeverity, severity);
            }
        }
    });

    // 6. DETECT COMBINATION PATTERNS (e.g., Name + Year or Name + Symbol + Year)
    const nameToken = tokens.find(t => t.category === "name" || t.category === "nickname" || t.category === "username");
    const yearToken = tokens.find(t => t.category === "birthYear" || t.category === "birthDate");

    if (nameToken && yearToken) {
        const nVal = nameToken.value;
        const yVal = yearToken.value;
        // Check if password has both name and year in proximity
        if (
            (passLower.includes(nVal) || passLeetspeak.includes(nVal)) &&
            passLower.includes(yVal)
        ) {
            const comboMatch = {
                category: "combination",
                label: "Personal Combination",
                matchType: "combination",
                description: `Combines your ${nameToken.label.toLowerCase()} ("${nameToken.originalCase}") and ${yearToken.label.toLowerCase()} ("${yearToken.value}").`,
                severity: 95
            };
            // Add if not already represented as a direct combo
            if (!matches.some(m => m.matchType === "combination")) {
                matches.push(comboMatch);
                explanations.push(`Combines personal identifier ("${nameToken.originalCase}") with birth information ("${yearToken.value}").`);
                totalSeverity = Math.max(totalSeverity, 95);
            }
        }
    }

    const similarityScore = Math.min(100, totalSeverity);
    const hasHighSimilarity = similarityScore >= 50;

    return {
        similarityScore,
        matches,
        hasHighSimilarity,
        explanations
    };
}
