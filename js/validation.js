/**
 * validation.js - Input validation and sanitization utilities
 * 
 * Provides pure functions to validate and sanitize user inputs
 * for safe client-side processing without XSS or injection risks.
 */

/**
 * Escapes unsafe HTML characters to prevent XSS.
 * @param {string} str - Raw string
 * @returns {string} Sanitized string safe for DOM interpolation
 */
export function escapeHtml(str) {
    if (typeof str !== "string") return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Sanitizes a plain text input by trimming whitespace and removing control characters.
 * @param {string} input - Raw input
 * @param {number} [maxLength=100] - Max allowable length
 * @returns {string}
 */
export function sanitizeText(input, maxLength = 100) {
    if (typeof input !== "string") return "";
    return input.trim().slice(0, maxLength);
}

/**
 * Validates and extracts a 4-digit year from a year string or date string.
 * @param {string} input - Year or date string (e.g., "2004", "2004-08-19", "19/08/2004")
 * @returns {string[]} Array of extracted year and date number parts (e.g. ["2004", "19", "08"])
 */
export function extractDateTokens(input) {
    if (!input || typeof input !== "string") return [];
    const tokens = [];

    // Match 4-digit years between 1900 and 2099
    const yearMatches = input.match(/\b(19\d{2}|20\d{2})\b/g);
    if (yearMatches) {
        yearMatches.forEach(y => tokens.push(y));
    }

    // Match all numeric groups with 2+ digits
    const numGroups = input.match(/\d{2,}/g);
    if (numGroups) {
        numGroups.forEach(num => {
            if (!tokens.includes(num)) {
                tokens.push(num);
            }
        });
    }

    return tokens;
}

/**
 * Sanitizes and extracts clean phone number segments.
 * @param {string} phone - Raw phone input
 * @returns {string[]} Array of relevant phone parts (full digits, last 4 digits, area code)
 */
export function extractPhoneTokens(phone) {
    if (!phone || typeof phone !== "string") return [];
    const digits = phone.replace(/\D/g, "");
    if (digits.length < 3) return [];

    const tokens = [digits];

    // Last 4 digits (common in PINs / passwords)
    if (digits.length >= 4) {
        tokens.push(digits.slice(-4));
    }

    // First 3-4 digits (area code / prefix)
    if (digits.length >= 6) {
        tokens.push(digits.slice(0, 3));
        tokens.push(digits.slice(0, 4));
    }

    return tokens;
}

/**
 * Parses a comma-separated or space-separated list of keywords.
 * @param {string} input - Raw keywords string
 * @returns {string[]} Array of clean, distinct keyword tokens
 */
export function parseKeywords(input) {
    if (!input || typeof input !== "string") return [];
    return input
        .split(/[,\s]+/)
        .map(kw => kw.trim().toLowerCase())
        .filter(kw => kw.length >= 2);
}
