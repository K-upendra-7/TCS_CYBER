/**
 * passwordAnalyzer.js - Password Strength & Security Analysis Engine
 * 
 * Implements the Adaptive Password Strength Scoring Algorithm (APSSA)
 * combined with Shannon entropy, crack time estimation, pattern detection,
 * dictionary matching, and personal data similarity weighting.
 */

import { analyzePasswordSimilarity } from "./passwordSimilarity.js";

// ========================================================
// COMMON PASSWORD DICTIONARY
// ========================================================
const COMMON_PASSWORDS = new Set([
    "password", "password1", "password123", "password123!", "passw0rd",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "zxcvbn",
    "admin", "admin123", "administrator", "welcome", "welcome123",
    "letmein", "login", "guest", "root", "root123", "secret", "secret123",
    "changeme", "abc123", "abc12345", "pass123", "pass1234",
    "hello", "hello123", "iloveyou", "monkey", "dragon", "football", "baseball",
    "master", "test", "test123", "sunshine", "princess", "superman", "trustno1",
    "000000", "111111", "222222", "333333", "444444", "555555",
    "666666", "777777", "888888", "999999"
]);

// ========================================================
// KEYBOARD PATTERNS
// ========================================================
const KEYBOARD_PATTERNS = [
    "qwerty", "qwertyui", "qwertyuiop",
    "asdfgh", "asdfghjk", "asdfghjkl",
    "zxcvbn", "zxcvbnm",
    "qazwsx", "wsxedc", "edcrfv", "rfvtgb", "tgbyhn", "yhnujm", "ujmikl",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,",
    "qwer", "wert", "erty", "rtyu", "tyui", "yuio", "uiop",
    "asdf", "sdfg", "dfgh", "fghj", "ghjk", "hjkl",
    "zxcv", "xcvb", "cvbn", "vbnm"
];

// ========================================================
// UTILITIES
// ========================================================
function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function hasLower(str) { return /[a-z]/.test(str); }
function hasUpper(str) { return /[A-Z]/.test(str); }
function hasDigit(str) { return /[0-9]/.test(str); }
function hasSpecial(str) { return /[^A-Za-z0-9]/.test(str); }

// ========================================================
// SHANNON ENTROPY CALCULATION
// ========================================================
export function calculateEntropy(password) {
    if (!password || !password.length) {
        return { entropy: 0, poolSize: 0, score: 0 };
    }

    let pool = 0;
    if (hasLower(password)) pool += 26;
    if (hasUpper(password)) pool += 26;
    if (hasDigit(password)) pool += 10;
    if (hasSpecial(password)) pool += 33;

    if (pool === 0) return { entropy: 0, poolSize: 0, score: 0 };

    const entropy = password.length * Math.log2(pool);

    let score = 0;
    if (entropy < 28) {
        score = (entropy / 28) * 20;
    } else if (entropy < 50) {
        score = 20 + ((entropy - 28) / 22) * 25;
    } else if (entropy < 70) {
        score = 45 + ((entropy - 50) / 20) * 25;
    } else if (entropy < 100) {
        score = 70 + ((entropy - 70) / 30) * 30;
    } else {
        score = 100;
    }

    return {
        entropy: Number(entropy.toFixed(1)),
        poolSize: pool,
        score: Math.round(clamp(score, 0, 100))
    };
}

// ========================================================
// CRACK TIME ESTIMATION
// ========================================================
export function calculateCrackTime(entropy) {
    if (entropy <= 0) return "Instant";

    // Assuming 10 billion guesses/second (modern GPU cluster)
    const guessesPerSecond = 10_000_000_000;
    const possibleCombinations = Math.pow(2, entropy);
    const seconds = possibleCombinations / guessesPerSecond;

    if (seconds < 0.001) return "Instant";
    if (seconds < 1) return "< 1 second";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 315360000) return `${Math.round(seconds / 31536000)} years`;
    if (seconds < 31536000000) return `${Math.round(seconds / 31536000).toLocaleString()} years`;
    if (seconds < 31536000000000) return `${Math.round(seconds / 31536000000).toLocaleString()} thousand years`;
    if (seconds < 31536000000000000) return `${Math.round(seconds / 31536000000000).toLocaleString()} million years`;
    return "Centuries / Billions of years";
}

// ========================================================
// LENGTH ANALYSIS
// ========================================================
function analyzeLength(password) {
    const length = password.length;
    let score = 0;

    if (length < 8) {
        score = (length / 8) * 30;
    } else if (length < 12) {
        score = 30 + ((length - 8) / 4) * 25;
    } else if (length < 16) {
        score = 55 + ((length - 12) / 4) * 25;
    } else if (length < 20) {
        score = 80 + ((length - 16) / 4) * 20;
    } else {
        score = 100;
    }

    return {
        length,
        score: Math.round(clamp(score, 0, 100)),
        isOptimal: length >= 14,
        isAcceptable: length >= 12,
        isShort: length < 8
    };
}

// ========================================================
// CHARACTER DIVERSITY
// ========================================================
function analyzeDiversity(password) {
    const categories = {
        lowercase: hasLower(password),
        uppercase: hasUpper(password),
        number: hasDigit(password),
        special: hasSpecial(password)
    };

    const count = Object.values(categories).filter(Boolean).length;
    return {
        categories,
        count,
        score: Math.round((count / 4) * 100)
    };
}

// ========================================================
// CHARACTER DISTRIBUTION
// ========================================================
function analyzeDistribution(password) {
    if (!password.length) return { score: 0, maxFrequency: 1, uniqueRatio: 0 };

    const frequency = new Map();
    for (const char of password) {
        frequency.set(char, (frequency.get(char) || 0) + 1);
    }

    let maxFrequency = 0;
    for (const count of frequency.values()) {
        maxFrequency = Math.max(maxFrequency, count / password.length);
    }

    const uniqueRatio = frequency.size / password.length;
    let score = 100;

    if (maxFrequency >= 0.70) score = 5;
    else if (maxFrequency >= 0.50) score = 25;
    else if (maxFrequency >= 0.35) score = 50;
    else if (maxFrequency >= 0.25) score = 75;

    if (uniqueRatio < 0.25) score -= 25;
    else if (uniqueRatio < 0.40) score -= 10;

    return {
        score: Math.round(clamp(score, 0, 100)),
        maxFrequency: Number(maxFrequency.toFixed(2)),
        uniqueRatio: Number(uniqueRatio.toFixed(2))
    };
}

// ========================================================
// SEQUENCE ANALYSIS (Dynamic Ascending / Descending)
// ========================================================
function analyzeSequence(password) {
    const value = password.toLowerCase();
    let longest = 1;
    let current = 1;
    let direction = 0;

    for (let i = 1; i < value.length; i++) {
        const diff = value.charCodeAt(i) - value.charCodeAt(i - 1);
        if (diff === 1 || diff === -1) {
            const newDir = diff > 0 ? 1 : -1;
            if (newDir === direction) {
                current++;
            } else {
                current = 2;
                direction = newDir;
            }
            longest = Math.max(longest, current);
        } else {
            current = 1;
            direction = 0;
        }
    }

    let risk = 0;
    if (longest >= 7) risk = 100;
    else if (longest >= 5) risk = 75;
    else if (longest >= 4) risk = 50;
    else if (longest >= 3) risk = 25;

    return { longest, risk, hasSequence: risk > 0 };
}

// ========================================================
// KEYBOARD PATTERNS
// ========================================================
function analyzeKeyboard(password) {
    const value = password.toLowerCase();
    let risk = 0;
    let matched = null;

    for (const pattern of KEYBOARD_PATTERNS) {
        if (value.includes(pattern)) {
            const currentRisk = pattern.length >= 7 ? 100 : pattern.length >= 5 ? 75 : 50;
            if (currentRisk > risk) {
                risk = currentRisk;
                matched = pattern;
            }
        }
    }

    return { risk, matched, hasKeyboardPattern: risk > 0 };
}

// ========================================================
// REPETITION & REPEATED BLOCKS
// ========================================================
function analyzeRepetition(password) {
    if (!password.length) return { maxRun: 0, risk: 0, hasRepeats: false };

    let maxRun = 1;
    let currentRun = 1;

    for (let i = 1; i < password.length; i++) {
        if (password[i] === password[i - 1]) {
            currentRun++;
            maxRun = Math.max(maxRun, currentRun);
        } else {
            currentRun = 1;
        }
    }

    let risk = 0;
    if (maxRun >= 6) risk = 100;
    else if (maxRun >= 5) risk = 80;
    else if (maxRun >= 4) risk = 60;
    else if (maxRun >= 3) risk = 30;

    return { maxRun, risk, hasRepeats: risk > 0 };
}

function analyzeRepeatedBlock(password) {
    const n = password.length;
    for (let size = 1; size <= Math.floor(n / 2); size++) {
        if (n % size !== 0) continue;
        const block = password.slice(0, size);
        const repetitions = n / size;
        if (repetitions < 3) continue;

        let valid = true;
        for (let i = size; i < n; i += size) {
            if (password.slice(i, i + size) !== block) {
                valid = false;
                break;
            }
        }

        if (valid) {
            return {
                risk: repetitions >= 5 ? 100 : 75,
                block,
                repetitions,
                hasRepeatedBlock: true
            };
        }
    }

    return { risk: 0, block: null, repetitions: 0, hasRepeatedBlock: false };
}

// ========================================================
// DICTIONARY & COMMON PASSWORD CHECK
// ========================================================
function analyzeDictionary(password) {
    const passLower = password.toLowerCase();
    const passClean = passLower.replace(/[^a-z0-9]/g, "");

    let risk = 0;
    let matchedWord = null;

    if (COMMON_PASSWORDS.has(passLower) || COMMON_PASSWORDS.has(passClean)) {
        return { risk: 100, similarity: 1.0, matchedWord: passLower, isCommon: true };
    }

    for (const common of COMMON_PASSWORDS) {
        if (common.length >= 4 && (passLower.includes(common) || passClean.includes(common))) {
            risk = 85;
            matchedWord = common;
            break;
        }
    }

    return {
        risk,
        similarity: risk ? 0.85 : 0,
        matchedWord,
        isCommon: risk >= 70
    };
}

// ========================================================
// PREDICTABLE STRUCTURES
// ========================================================
function analyzePredictability(password) {
    let risk = 0;
    const patterns = [];

    if (/^[A-Za-z]+[0-9]+$/.test(password)) {
        risk += 30;
        patterns.push("Word followed by number (e.g. Word123)");
    }

    if (/^[A-Za-z]+[^A-Za-z0-9]+[0-9]+$/.test(password)) {
        risk += 30;
        patterns.push("Word + Symbol + Number (e.g. Word@123)");
    }

    if (/(19|20)\d{2}/.test(password)) {
        risk += 25;
        patterns.push("Recognizable 4-digit year (19xx / 20xx)");
    }

    if (/\d{3,}$/.test(password)) {
        risk += 20;
        patterns.push("Sequential numeric suffix");
    }

    return {
        risk: clamp(risk, 0, 100),
        patterns,
        isPredictable: risk > 0
    };
}

// ========================================================
// OVERALL SCORING & ADAPTIVE CAPPING
// ========================================================
function calculateFinalScore(analysis) {
    const { length, entropy, diversity, distribution, predictabilityRisk, similarityRisk } = analysis;

    const positiveCapability =
        length.score * 0.25 +
        entropy.score * 0.20 +
        diversity.score * 0.15 +
        distribution.score * 0.10 +
        (100 - predictabilityRisk) * 0.30;

    let score = positiveCapability;

    // Penalty for personal similarity
    if (similarityRisk > 0) {
        score -= (similarityRisk * 0.35);
    }

    // Adaptive Caps
    if (analysis.dictionary.risk >= 100) score = Math.min(score, 15);
    else if (analysis.dictionary.risk >= 70) score = Math.min(score, 30);

    if (similarityRisk >= 85) score = Math.min(score, 25);
    else if (similarityRisk >= 50) score = Math.min(score, 45);

    if (analysis.repetition.risk >= 80 || analysis.repeatedBlock.risk >= 75) score = Math.min(score, 25);
    if (analysis.sequence.risk >= 75) score = Math.min(score, 35);
    if (analysis.keyboard.risk >= 75) score = Math.min(score, 35);
    if (distribution.score <= 10) score = Math.min(score, 30);

    if (length.length < 8) score = Math.min(score, 25);
    else if (length.length < 12) score = Math.min(score, 55);

    return Math.round(clamp(score, 0, 100));
}

// ========================================================
// CLASSIFICATION LEVEL
// ========================================================
export function getStrengthClassification(score) {
    if (score < 25) {
        return { label: "VERY WEAK", color: "#ef4444", progressColor: "#ef4444", key: "very-weak" };
    }
    if (score < 50) {
        return { label: "WEAK", color: "#f97316", progressColor: "#f97316", key: "weak" };
    }
    if (score < 70) {
        return { label: "MODERATE", color: "#eab308", progressColor: "#eab308", key: "moderate" };
    }
    if (score < 85) {
        return { label: "STRONG", color: "#10b981", progressColor: "#10b981", key: "strong" };
    }
    return { label: "VERY STRONG", color: "#06b6d4", progressColor: "#06b6d4", key: "very-strong" };
}

// ========================================================
// FINDINGS & RECOMMENDATIONS GENERATION
// ========================================================
function generateFindingsAndRecommendations(analysis, score) {
    const findings = [];
    const recommendations = [];

    // Length
    if (analysis.length.length < 8) {
        findings.push("Critically short: Under 8 characters can be brute-forced in seconds.");
        recommendations.push("Increase password length to at least 12–16 characters.");
    } else if (analysis.length.length < 12) {
        findings.push("Length below recommended minimum (12+ characters).");
        recommendations.push("Expand length to 12 or more characters to dramatically increase entropy.");
    } else {
        findings.push(`Good length: ${analysis.length.length} characters.`);
    }

    // Diversity
    if (analysis.diversity.count < 3) {
        findings.push(`Limited character diversity: uses only ${analysis.diversity.count} character type(s).`);
        recommendations.push("Combine uppercase letters, lowercase letters, numbers, and special symbols.");
    }

    // Common dictionary
    if (analysis.dictionary.isCommon) {
        findings.push(`Matches or contains a common password pattern ("${analysis.dictionary.matchedWord}").`);
        recommendations.push("Avoid well-known words and dictionary terms.");
    }

    // Sequences
    if (analysis.sequence.hasSequence) {
        findings.push(`Contains a predictable character sequence (run of ${analysis.sequence.longest}).`);
        recommendations.push("Avoid alphabetical or numeric sequences like 1234 or abcd.");
    }

    // Keyboard patterns
    if (analysis.keyboard.hasKeyboardPattern) {
        findings.push(`Contains a common keyboard walk ("${analysis.keyboard.matched}").`);
        recommendations.push("Avoid standard keyboard layouts like qwerty or asdf.");
    }

    // Repetition
    if (analysis.repetition.hasRepeats || analysis.repeatedBlock.hasRepeatedBlock) {
        findings.push("Contains excessive repeating characters or repeating sub-blocks.");
        recommendations.push("Avoid repeating identical characters consecutively.");
    }

    // Predictable structures
    if (analysis.predictability.isPredictable) {
        analysis.predictability.patterns.forEach(pat => {
            findings.push(`Predictable structure: ${pat}.`);
        });
        recommendations.push("Avoid standard formulaic structures like Word + Symbol + Year.");
    }

    // Personal similarity
    if (analysis.similarity.matches.length > 0) {
        analysis.similarity.matches.forEach(m => {
            findings.push(`Personal data similarity: ${m.description}`);
        });
        recommendations.push("Do not include your name, username, birth date, phone number, or keywords.");
    }

    // Overall positive
    if (score >= 80 && recommendations.length === 0) {
        findings.push("Entropy and unpredictability meet enterprise cybersecurity standards.");
        recommendations.push("Keep this password unique. Never reuse it across multiple accounts.");
        recommendations.push("Enable Multi-Factor Authentication (MFA/2FA) on critical accounts.");
    }

    return { findings, recommendations };
}

// ========================================================
// MAIN ANALYZER FUNCTION
// ========================================================
/**
 * Analyzes password against standard rules, APSSA metrics, and user personal tokens.
 * @param {string} password - The password string
 * @param {Array<import('./userData.js').PersonalToken>} [personalTokens=[]] - Personal tokens
 * @returns {Object} Complete analysis report
 */
export function analyzePassword(password, personalTokens = []) {
    if (!password || typeof password !== "string") {
        return null;
    }

    const length = analyzeLength(password);
    const diversity = analyzeDiversity(password);
    const entropy = calculateEntropy(password);
    const crackTime = calculateCrackTime(entropy.entropy);
    const distribution = analyzeDistribution(password);
    const sequence = analyzeSequence(password);
    const keyboard = analyzeKeyboard(password);
    const repetition = analyzeRepetition(password);
    const repeatedBlock = analyzeRepeatedBlock(password);
    const dictionary = analyzeDictionary(password);
    const predictability = analyzePredictability(password);
    const similarity = analyzePasswordSimilarity(password, personalTokens);

    // Calculate predictability risk
    const predictabilityRisk = Math.round(clamp(
        dictionary.risk * 0.28 +
        similarity.similarityScore * 0.25 +
        sequence.risk * 0.10 +
        keyboard.risk * 0.10 +
        repetition.risk * 0.12 +
        repeatedBlock.risk * 0.08 +
        predictability.risk * 0.07,
        0, 100
    ));

    const analysisObj = {
        password,
        length,
        diversity,
        entropy,
        crackTime,
        distribution,
        sequence,
        keyboard,
        repetition,
        repeatedBlock,
        dictionary,
        predictability,
        similarity,
        similarityRisk: similarity.similarityScore,
        predictabilityRisk
    };

    const score = calculateFinalScore(analysisObj);
    const strength = getStrengthClassification(score);
    const { findings, recommendations } = generateFindingsAndRecommendations(analysisObj, score);

    // Checklist pass/fail states
    const checks = {
        length: length.length >= 12,
        uppercase: diversity.categories.uppercase,
        lowercase: diversity.categories.lowercase,
        number: diversity.categories.number,
        special: diversity.categories.special,
        repeat: !repetition.hasRepeats && !repeatedBlock.hasRepeatedBlock,
        sequence: !sequence.hasSequence,
        keyboard: !keyboard.hasKeyboardPattern,
        common: !dictionary.isCommon,
        personalData: !similarity.hasHighSimilarity
    };

    return {
        score,
        strength,
        entropy: entropy.entropy,
        crackTime,
        checks,
        findings,
        recommendations,
        similarity,
        details: analysisObj
    };
}

// ========================================================
// CRYPTOGRAPHICALLY SECURE PASSWORD GENERATOR
// ========================================================
/**
 * Generates a high-entropy password using crypto.getRandomValues().
 * @param {Object} options
 * @param {number} [options.length=18]
 * @param {boolean} [options.uppercase=true]
 * @param {boolean} [options.lowercase=true]
 * @param {boolean} [options.numbers=true]
 * @param {boolean} [options.symbols=true]
 * @param {boolean} [options.avoidAmbiguous=false]
 * @returns {string}
 */
export function generateSecurePassword(options = {}) {
    const {
        length = 18,
        uppercase = true,
        lowercase = true,
        numbers = true,
        symbols = true,
        avoidAmbiguous = false
    } = options;

    let upperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lowerSet = "abcdefghijklmnopqrstuvwxyz";
    let numSet = "0123456789";
    let symSet = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    if (avoidAmbiguous) {
        // Remove visually confusing chars: O, 0, I, l, 1, |, `
        upperSet = upperSet.replace(/[OI]/g, "");
        lowerSet = lowerSet.replace(/[l]/g, "");
        numSet = numSet.replace(/[01]/g, "");
        symSet = symSet.replace(/[|]/g, "");
    }

    const sets = [];
    if (uppercase) sets.push(upperSet);
    if (lowercase) sets.push(lowerSet);
    if (numbers) sets.push(numSet);
    if (symbols) sets.push(symSet);

    if (sets.length === 0) {
        sets.push(lowerSet, numSet);
    }

    const allChars = sets.join("");
    const result = [];

    // Guarantee at least one character from each selected set
    for (const set of sets) {
        result.push(getRandomCharFrom(set));
    }

    // Fill remaining
    while (result.length < length) {
        result.push(getRandomCharFrom(allChars));
    }

    // Cryptographic Fisher-Yates shuffle
    for (let i = result.length - 1; i > 0; i--) {
        const j = getSecureRandomInt(i + 1);
        [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join("");
}

function getSecureRandomInt(max) {
    if (max <= 0) return 0;
    const array = new Uint32Array(1);
    const range = Math.floor(0xFFFFFFFF / max) * max;
    let random;
    do {
        crypto.getRandomValues(array);
        random = array[0];
    } while (random >= range);
    return random % max;
}

function getRandomCharFrom(charset) {
    const index = getSecureRandomInt(charset.length);
    return charset[index];
}
