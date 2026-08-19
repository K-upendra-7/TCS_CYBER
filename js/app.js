/**
 * app.js - Application Initialization and Event Coordinator
 * 
 * Sets up modules, manages state, binds event listeners, and drives
 * the real-time password analysis workflow.
 */

import { processUserData } from "./userData.js";
import { analyzePassword, generateSecurePassword } from "./passwordAnalyzer.js";
import { UIController } from "./ui.js";

class App {
    constructor() {
        this.ui = new UIController();
        this.personalTokens = [];
        this.currentPassword = "";
        this._debounceTimer = null;
    }

    /**
     * Initializes the application.
     */
    init() {
        this.ui.init();
        this.bindEvents();
        this.updatePersonalData();
        this.runAnalysis();
    }

    /**
     * Extracts personal info from form and updates active tokens.
     */
    updatePersonalData() {
        const rawData = {
            fullName: this.ui.elements.fullNameInput ? this.ui.elements.fullNameInput.value : "",
            nickname: this.ui.elements.nicknameInput ? this.ui.elements.nicknameInput.value : "",
            birthDate: this.ui.elements.birthDateInput ? this.ui.elements.birthDateInput.value : "",
            username: this.ui.elements.usernameInput ? this.ui.elements.usernameInput.value : "",
            email: this.ui.elements.emailInput ? this.ui.elements.emailInput.value : "",
            phone: this.ui.elements.phoneInput ? this.ui.elements.phoneInput.value : "",
            keywords: this.ui.elements.keywordsInput ? this.ui.elements.keywordsInput.value : ""
        };

        this.personalTokens = processUserData(rawData);
        this.ui.updatePersonalDataCount(this.personalTokens.length);
    }

    /**
     * Runs password analysis and updates UI.
     */
    runAnalysis() {
        const password = this.ui.elements.passwordInput ? this.ui.elements.passwordInput.value : "";
        this.currentPassword = password;

        if (!password) {
            this.ui.resetDashboard();
            return;
        }

        const report = analyzePassword(password, this.personalTokens);
        this.ui.updateDashboard(report);
    }

    /**
     * Schedules a debounced analysis run (for optimal responsiveness).
     */
    scheduleAnalysis() {
        clearTimeout(this._debounceTimer);
        this._debounceTimer = setTimeout(() => {
            this.runAnalysis();
        }, 60);
    }

    /**
     * Binds all DOM event listeners.
     */
    bindEvents() {
        const { elements } = this.ui;

        // 1. Password input event
        if (elements.passwordInput) {
            elements.passwordInput.addEventListener("input", () => {
                this.scheduleAnalysis();
            });
        }

        // 2. Personal info inputs events
        const personalInputs = [
            elements.fullNameInput,
            elements.nicknameInput,
            elements.birthDateInput,
            elements.usernameInput,
            elements.emailInput,
            elements.phoneInput,
            elements.keywordsInput
        ];

        personalInputs.forEach(input => {
            if (input) {
                input.addEventListener("input", () => {
                    this.updatePersonalData();
                    this.scheduleAnalysis();
                });
            }
        });

        // 3. Toggle Password Visibility
        if (elements.togglePasswordBtn && elements.passwordInput) {
            elements.togglePasswordBtn.addEventListener("click", () => {
                const isPassword = elements.passwordInput.type === "password";
                elements.passwordInput.type = isPassword ? "text" : "password";
                elements.togglePasswordBtn.textContent = isPassword ? "HIDE" : "SHOW";
                elements.togglePasswordBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
            });
        }

        // 4. Copy Password to Clipboard
        if (elements.copyPasswordBtn && elements.passwordInput) {
            elements.copyPasswordBtn.addEventListener("click", async () => {
                const val = elements.passwordInput.value;
                if (!val) {
                    this.ui.showToast("No password to copy!", "warning");
                    return;
                }

                try {
                    await navigator.clipboard.writeText(val);
                    this.ui.showToast("Password copied to clipboard!", "success");
                } catch {
                    // Fallback
                    elements.passwordInput.select();
                    document.execCommand("copy");
                    this.ui.showToast("Password copied to clipboard!", "success");
                }
            });
        }

        // 5. Clear Password
        if (elements.clearPasswordBtn && elements.passwordInput) {
            elements.clearPasswordBtn.addEventListener("click", () => {
                elements.passwordInput.value = "";
                elements.passwordInput.focus();
                this.runAnalysis();
                this.ui.showToast("Password field cleared", "info");
            });
        }

        // 6. Generator Modal / Controls
        this.bindGeneratorEvents();
    }

    /**
     * Binds password generator modal and options.
     */
    bindGeneratorEvents() {
        const { elements } = this.ui;

        const getGeneratorOptions = () => ({
            length: elements.genLengthSlider ? parseInt(elements.genLengthSlider.value, 10) : 18,
            uppercase: elements.genUpperCheck ? elements.genUpperCheck.checked : true,
            lowercase: elements.genLowerCheck ? elements.genLowerCheck.checked : true,
            numbers: elements.genNumCheck ? elements.genNumCheck.checked : true,
            symbols: elements.genSymCheck ? elements.genSymCheck.checked : true,
            avoidAmbiguous: elements.genAvoidAmbiguous ? elements.genAvoidAmbiguous.checked : false
        });

        const refreshPreview = () => {
            const pwd = generateSecurePassword(getGeneratorOptions());
            if (elements.previewGeneratedText) {
                elements.previewGeneratedText.value = pwd;
            }
            return pwd;
        };

        // Open Generator Modal / Quick Action
        if (elements.generateBtn) {
            elements.generateBtn.addEventListener("click", () => {
                if (elements.generatorModal) {
                    elements.generatorModal.classList.add("modal-active");
                    refreshPreview();
                } else {
                    // Fallback quick generation directly to input
                    const newPwd = generateSecurePassword({ length: 18 });
                    if (elements.passwordInput) {
                        elements.passwordInput.value = newPwd;
                        elements.passwordInput.type = "text";
                        if (elements.togglePasswordBtn) elements.togglePasswordBtn.textContent = "HIDE";
                        this.runAnalysis();
                        this.ui.showToast("Generated new strong password!", "success");
                    }
                }
            });
        }

        // Close Generator Modal
        if (elements.closeGeneratorBtn && elements.generatorModal) {
            elements.closeGeneratorBtn.addEventListener("click", () => {
                elements.generatorModal.classList.remove("modal-active");
            });
        }

        // Modal backdrop click
        if (elements.generatorModal) {
            elements.generatorModal.addEventListener("click", (e) => {
                if (e.target === elements.generatorModal) {
                    elements.generatorModal.classList.remove("modal-active");
                }
            });
        }

        // Slider value update
        if (elements.genLengthSlider && elements.genLengthVal) {
            elements.genLengthSlider.addEventListener("input", () => {
                elements.genLengthVal.textContent = elements.genLengthSlider.value;
                refreshPreview();
            });
        }

        // Checkbox changes refresh preview
        [
            elements.genUpperCheck,
            elements.genLowerCheck,
            elements.genNumCheck,
            elements.genSymCheck,
            elements.genAvoidAmbiguous
        ].forEach(cb => {
            if (cb) {
                cb.addEventListener("change", refreshPreview);
            }
        });

        // Regenerate Button
        if (elements.regenBtn) {
            elements.regenBtn.addEventListener("click", refreshPreview);
        }

        // Apply Generated to Password Input
        if (elements.applyGeneratedBtn && elements.passwordInput) {
            elements.applyGeneratedBtn.addEventListener("click", () => {
                const generated = elements.previewGeneratedText ? elements.previewGeneratedText.value : refreshPreview();
                elements.passwordInput.value = generated;
                elements.passwordInput.type = "text";
                if (elements.togglePasswordBtn) elements.togglePasswordBtn.textContent = "HIDE";
                if (elements.generatorModal) elements.generatorModal.classList.remove("modal-active");
                this.runAnalysis();
                this.ui.showToast("Applied generated password!", "success");
            });
        }
    }
}

// Bootstrap on DOMContentLoaded
document.addEventListener("DOMContentLoaded", () => {
    const app = new App();
    app.init();
});
