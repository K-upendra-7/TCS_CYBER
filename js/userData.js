/**
 * userData.js - User Personal Information Collector and Processor
 * 
 * Collects, sanitizes, and prepares user personal data for local similarity analysis.
 * Note: All user data is processed strictly in client-side memory and never persisted or transmitted.
 */

import { sanitizeText, extractDateTokens, extractPhoneTokens, parseKeywords } from "./validation.js";

/**
 * @typedef {Object} PersonalToken
 * @property {string} category - Category of personal data (name, nickname, birthYear, username, email, phone, keyword)
 * @property {string} label - Human-friendly label for display in alerts
 * @property {string} value - The extracted token value
 * @property {number} weight - Relative risk severity (1.0 = full name/username, 0.7 = partials)
 */

/**
 * Extracts and tokenizes all provided personal information.
 * @param {Object} rawData - Object containing raw form values
 * @param {string} [rawData.fullName]
 * @param {string} [rawData.nickname]
 * @param {string} [rawData.birthDate]
 * @param {string} [rawData.username]
 * @param {string} [rawData.email]
 * @param {string} [rawData.phone]
 * @param {string} [rawData.keywords]
 * @returns {PersonalToken[]} Array of structured personal tokens for analysis
 */
export function processUserData(rawData = {}) {
    const tokens = [];
    const seen = new Set();

    function addToken(category, label, rawVal, weight = 1.0) {
        if (!rawVal || typeof rawVal !== "string") return;
        const val = rawVal.trim().toLowerCase();
        if (val.length < 2) return; // Ignore single characters to prevent false positives

        const key = `${category}:${val}`;
        if (!seen.has(key)) {
            seen.add(key);
            tokens.push({
                category,
                label,
                value: val,
                originalCase: rawVal.trim(),
                weight
            });
        }
    }

    // 1. Full Name & Name parts (first name, last name)
    const fullName = sanitizeText(rawData.fullName || "");
    if (fullName) {
        addToken("name", "Full Name", fullName, 1.0);
        // Split name into parts (e.g., "Kolla Upendra" -> "kolla", "upendra")
        const parts = fullName.split(/\s+/);
        if (parts.length > 1) {
            parts.forEach(part => {
                if (part.length >= 3) {
                    addToken("name", "Name Part", part, 0.9);
                }
            });
        }
    }

    // 2. Nickname
    const nickname = sanitizeText(rawData.nickname || "");
    if (nickname) {
        addToken("nickname", "Nickname", nickname, 1.0);
    }

    // 3. Username
    const username = sanitizeText(rawData.username || "");
    if (username) {
        addToken("username", "Username", username, 1.0);
    }

    // 4. Email address (extract username part and domain name)
    const email = sanitizeText(rawData.email || "");
    if (email && email.includes("@")) {
        const [emailUser, domainPart] = email.split("@");
        if (emailUser && emailUser.length >= 3) {
            addToken("email", "Email Identifier", emailUser, 0.9);
        }
        if (domainPart) {
            const domainName = domainPart.split(".")[0];
            if (domainName && domainName.length >= 4 && !["gmail", "yahoo", "outlook", "hotmail", "icloud"].includes(domainName.toLowerCase())) {
                addToken("emailDomain", "Email Domain", domainName, 0.6);
            }
        }
    }

    // 5. Date of Birth / Birth Year
    const birthDate = sanitizeText(rawData.birthDate || "");
    if (birthDate) {
        const dateTokens = extractDateTokens(birthDate);
        dateTokens.forEach(dt => {
            if (dt.length === 4) {
                addToken("birthYear", "Birth Year", dt, 0.95);
            } else if (dt.length >= 2) {
                addToken("birthDate", "Birth Date Segment", dt, 0.7);
            }
        });
    }

    // 6. Phone Number
    const phone = sanitizeText(rawData.phone || "");
    if (phone) {
        const phoneTokens = extractPhoneTokens(phone);
        phoneTokens.forEach(pt => {
            if (pt.length >= 6) {
                addToken("phone", "Phone Number", pt, 1.0);
            } else if (pt.length === 4) {
                addToken("phone", "Phone Last 4 Digits", pt, 0.85);
            }
        });
    }

    // 7. Custom Keywords / Pet / Partner / Favorite Words
    const keywords = sanitizeText(rawData.keywords || "");
    if (keywords) {
        const parsedKeywords = parseKeywords(keywords);
        parsedKeywords.forEach(kw => {
            addToken("keyword", `Keyword "${kw}"`, kw, 0.85);
        });
    }

    return tokens;
}
