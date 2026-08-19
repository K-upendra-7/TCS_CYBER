/**
 * ui.js - DOM manipulation, dashboard updates, and visual rendering
 * 
 * Provides a clean interface for updating all UI components, strength bars,
 * checklist indicators, similarity alerts, and recommendations.
 */

import { escapeHtml } from "./validation.js";

export class UIController {
    constructor() {
        this.elements = {
            // Inputs
            passwordInput: document.getElementById("password"),
            togglePasswordBtn: document.getElementById("togglePassword"),
            copyPasswordBtn: document.getElementById("copyPassword"),
            clearPasswordBtn: document.getElementById("clearPassword"),

            // Personal Info Form
            personalForm: document.getElementById("personalInfoForm"),
            fullNameInput: document.getElementById("fullName"),
            nicknameInput: document.getElementById("nickname"),
            birthDateInput: document.getElementById("birthDate"),
            usernameInput: document.getElementById("username"),
            emailInput: document.getElementById("email"),
            phoneInput: document.getElementById("phone"),
            keywordsInput: document.getElementById("keywords"),
            personalBadge: document.getElementById("personalDataCountBadge"),

            // Strength Metric Elements
            scoreText: document.getElementById("scoreText"),
            strengthText: document.getElementById("strengthText"),
            strengthProgress: document.getElementById("strengthProgress"),
            entropyText: document.getElementById("entropyText"),
            crackTimeText: document.getElementById("crackTimeText"),

            // Checks
            checks: {
                length: document.getElementById("lengthCheck"),
                uppercase: document.getElementById("uppercaseCheck"),
                lowercase: document.getElementById("lowercaseCheck"),
                number: document.getElementById("numberCheck"),
                special: document.getElementById("specialCheck"),
                repeat: document.getElementById("repeatCheck"),
                sequence: document.getElementById("sequenceCheck"),
                keyboard: document.getElementById("keyboardCheck"),
                common: document.getElementById("commonCheck"),
                personalData: document.getElementById("personalDataCheck")
            },

            // Diagnostics & Panels
            similarityCard: document.getElementById("similarityCard"),
            similarityList: document.getElementById("similarityList"),
            similaritySummary: document.getElementById("similaritySummary"),
            findingsBox: document.getElementById("findingsBox"),
            recommendationsBox: document.getElementById("recommendationsBox"),

            // Generator controls
            generateBtn: document.getElementById("generatePassword"),
            generatorModal: document.getElementById("generatorModal"),
            genLengthSlider: document.getElementById("genLengthSlider"),
            genLengthVal: document.getElementById("genLengthVal"),
            genUpperCheck: document.getElementById("genUpper"),
            genLowerCheck: document.getElementById("genLower"),
            genNumCheck: document.getElementById("genNum"),
            genSymCheck: document.getElementById("genSym"),
            genAvoidAmbiguous: document.getElementById("genAvoidAmbiguous"),
            applyGeneratedBtn: document.getElementById("applyGeneratedBtn"),
            closeGeneratorBtn: document.getElementById("closeGeneratorBtn"),
            previewGeneratedText: document.getElementById("previewGeneratedText"),
            regenBtn: document.getElementById("regenBtn")
        };
    }

    /**
     * Initializes UI state and base event listeners.
     */
    init() {
        this.resetDashboard();
    }

    /**
     * Resets dashboard to its initial default state.
     */
    resetDashboard() {
        if (this.elements.scoreText) this.elements.scoreText.textContent = "0";
        if (this.elements.strengthText) {
            this.elements.strengthText.textContent = "WAITING FOR INPUT";
            this.elements.strengthText.style.color = "var(--text-muted)";
        }
        if (this.elements.strengthProgress) {
            this.elements.strengthProgress.style.width = "0%";
            this.elements.strengthProgress.style.backgroundColor = "var(--border-color)";
        }
        if (this.elements.entropyText) this.elements.entropyText.textContent = "0 bits";
        if (this.elements.crackTimeText) this.elements.crackTimeText.textContent = "—";

        // Reset check elements
        Object.values(this.elements.checks).forEach(el => {
            if (!el) return;
            el.classList.remove("check-passed", "check-failed");
            const icon = el.querySelector(".check-status-icon");
            if (icon) icon.textContent = "○";
        });

        // Reset Similarity Card
        if (this.elements.similarityCard) {
            this.elements.similarityCard.style.display = "none";
        }

        // Reset Findings Box
        if (this.elements.findingsBox) {
            this.elements.findingsBox.innerHTML = `
                <div class="empty-state-notice">
                    <span class="empty-icon">🛡️</span>
                    <p>Enter a password to run the real-time security diagnostics.</p>
                </div>
            `;
        }

        // Reset Recommendations Box
        if (this.elements.recommendationsBox) {
            this.elements.recommendationsBox.innerHTML = `
                <div class="empty-state-notice">
                    <span class="empty-icon">💡</span>
                    <p>Security recommendations will appear here based on your password strength.</p>
                </div>
            `;
        }
    }

    /**
     * Updates check item pass/fail styling.
     * @param {HTMLElement} element 
     * @param {boolean} passed 
     */
    updateCheckItem(element, passed) {
        if (!element) return;
        const icon = element.querySelector(".check-status-icon");

        if (passed) {
            element.classList.add("check-passed");
            element.classList.remove("check-failed");
            if (icon) icon.textContent = "✓";
        } else {
            element.classList.add("check-failed");
            element.classList.remove("check-passed");
            if (icon) icon.textContent = "✕";
        }
    }

    /**
     * Updates all UI elements with analysis results.
     * @param {Object} report - Result from analyzePassword()
     */
    updateDashboard(report) {
        if (!report) {
            this.resetDashboard();
            return;
        }

        const { score, strength, entropy, crackTime, checks, findings, recommendations, similarity } = report;

        // 1. Update Score & Classification
        if (this.elements.scoreText) {
            this.elements.scoreText.textContent = score;
            this.elements.scoreText.style.color = strength.color;
        }
        if (this.elements.strengthText) {
            this.elements.strengthText.textContent = strength.label;
            this.elements.strengthText.style.color = strength.color;
        }
        if (this.elements.strengthProgress) {
            this.elements.strengthProgress.style.width = `${Math.max(4, score)}%`;
            this.elements.strengthProgress.style.backgroundColor = strength.color;
            this.elements.strengthProgress.style.boxShadow = `0 0 12px ${strength.color}66`;
        }

        // 2. Update Entropy & Crack Time
        if (this.elements.entropyText) {
            this.elements.entropyText.textContent = `${entropy} bits`;
        }
        if (this.elements.crackTimeText) {
            this.elements.crackTimeText.textContent = crackTime;
            this.elements.crackTimeText.style.color = score >= 75 ? "var(--color-success)" : score >= 50 ? "var(--color-warning)" : "var(--color-danger)";
        }

        // 3. Update Security Checklist
        this.updateCheckItem(this.elements.checks.length, checks.length);
        this.updateCheckItem(this.elements.checks.uppercase, checks.uppercase);
        this.updateCheckItem(this.elements.checks.lowercase, checks.lowercase);
        this.updateCheckItem(this.elements.checks.number, checks.number);
        this.updateCheckItem(this.elements.checks.special, checks.special);
        this.updateCheckItem(this.elements.checks.repeat, checks.repeat);
        this.updateCheckItem(this.elements.checks.sequence, checks.sequence);
        this.updateCheckItem(this.elements.checks.keyboard, checks.keyboard);
        this.updateCheckItem(this.elements.checks.common, checks.common);
        this.updateCheckItem(this.elements.checks.personalData, checks.personalData);

        // 4. Update Similarity Alert Card
        if (this.elements.similarityCard && this.elements.similarityList) {
            if (similarity.matches && similarity.matches.length > 0) {
                this.elements.similarityCard.style.display = "block";
                if (this.elements.similaritySummary) {
                    this.elements.similaritySummary.textContent = `${similarity.matches.length} Personal Pattern(s) Detected`;
                }

                this.elements.similarityList.innerHTML = similarity.matches.map(m => `
                    <div class="similarity-match-item">
                        <div class="similarity-match-header">
                            <span class="match-badge match-badge-${escapeHtml(m.matchType)}">${escapeHtml(m.matchType.toUpperCase())}</span>
                            <span class="match-token-label">${escapeHtml(m.label)}</span>
                        </div>
                        <p class="match-desc">${escapeHtml(m.description)}</p>
                    </div>
                `).join("");
            } else {
                this.elements.similarityCard.style.display = "none";
            }
        }

        // 5. Update Findings Diagnostics
        if (this.elements.findingsBox) {
            this.elements.findingsBox.innerHTML = `
                <ul class="analysis-list">
                    ${findings.map(f => `
                        <li class="finding-item">
                            <span class="bullet-icon">›</span>
                            <span>${escapeHtml(f)}</span>
                        </li>
                    `).join("")}
                </ul>
            `;
        }

        // 6. Update Recommendations
        if (this.elements.recommendationsBox) {
            this.elements.recommendationsBox.innerHTML = `
                <ul class="recommendation-list">
                    ${recommendations.map(r => `
                        <li class="recommendation-item">
                            <span class="rec-icon">⚡</span>
                            <span>${escapeHtml(r)}</span>
                        </li>
                    `).join("")}
                </ul>
            `;
        }
    }

    /**
     * Displays a temporary toast notification.
     * @param {string} message 
     * @param {string} [type='info'] 
     */
    showToast(message, type = "info") {
        let toast = document.getElementById("appToast");
        if (!toast) {
            toast = document.createElement("div");
            toast.id = "appToast";
            toast.className = "app-toast";
            document.body.appendChild(toast);
        }

        toast.textContent = message;
        toast.className = `app-toast toast-${type} toast-visible`;

        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => {
            toast.classList.remove("toast-visible");
        }, 2500);
    }

    /**
     * Updates personal token counter badge.
     * @param {number} count 
     */
    updatePersonalDataCount(count) {
        if (this.elements.personalBadge) {
            this.elements.personalBadge.textContent = count > 0 ? `${count} Active Details` : "0 Details (Optional)";
            this.elements.personalBadge.className = count > 0 ? "badge badge-active" : "badge badge-muted";
        }
    }
}
