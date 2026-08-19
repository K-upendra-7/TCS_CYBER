"use strict";

/*
===========================================================
        APSSA - ADAPTIVE PASSWORD STRENGTH
        SCORING ALGORITHM

        Frontend-only cybersecurity analyzer

        Score:
        0 - 100

        Positive factors:
        - Length
        - Character diversity
        - Theoretical entropy
        - Character distribution
        - Unpredictability

        Negative factors:
        - Common passwords
        - Dictionary similarity
        - Username similarity
        - Sequences
        - Keyboard patterns
        - Repetition
        - Repeated blocks
        - Predictable structures
        - Leetspeak

        Password is NEVER sent anywhere.
===========================================================
*/


// ========================================================
// CONFIGURATION
// ========================================================

const CONFIG = {
    MAX_LENGTH: 64,

    LEVELS: [
        { min: 90, label: "EXCELLENT" },
        { min: 75, label: "STRONG" },
        { min: 60, label: "MODERATE" },
        { min: 40, label: "WEAK" },
        { min: 20, label: "VERY WEAK" },
        { min: 0, label: "EXTREMELY WEAK" }
    ]
};


// ========================================================
// COMMON PASSWORD DATA
// ========================================================

const COMMON_PASSWORDS = new Set([
    "password",
    "password1",
    "password123",
    "passw0rd",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "administrator",
    "welcome",
    "welcome123",
    "letmein",
    "login",
    "guest",
    "root",
    "secret",
    "changeme",
    "abc123",
    "hello",
    "hello123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "test",
    "test123",
    "sunshine",
    "princess",
    "superman",
    "trustno1"
]);


// ========================================================
// KEYBOARD PATTERNS
// ========================================================

const KEYBOARD_PATTERNS = [
    "qwerty",
    "qwertyui",
    "asdfgh",
    "asdfghjk",
    "zxcvbn",
    "zxcvbnm",
    "qazwsx",
    "wsxedc",
    "edcrfv",
    "rfvtgb",
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb"
];


// ========================================================
// DOM ELEMENTS
// ========================================================

const usernameInput =
    document.getElementById("username");

const passwordInput =
    document.getElementById("password");

const togglePassword =
    document.getElementById("togglePassword");

const scoreText =
    document.getElementById("scoreText");

const strengthProgress =
    document.getElementById("strengthProgress");

const strengthText =
    document.getElementById("strengthText");

const recommendationBox =
    document.getElementById("recommendationBox");

const generateButton =
    document.getElementById("generatePassword");


// ========================================================
// CHECK ELEMENTS
// ========================================================

const checks = {

    length:
        document.getElementById("lengthCheck"),

    uppercase:
        document.getElementById("uppercaseCheck"),

    lowercase:
        document.getElementById("lowercaseCheck"),

    number:
        document.getElementById("numberCheck"),

    special:
        document.getElementById("specialCheck"),

    repeat:
        document.getElementById("repeatCheck"),

    sequence:
        document.getElementById("sequenceCheck"),

    username:
        document.getElementById("usernameCheck"),

    common:
        document.getElementById("commonCheck")
};


// ========================================================
// UTILITY
// ========================================================

function clamp(value, min, max) {

    return Math.max(
        min,
        Math.min(max, value)
    );
}


function hasLowercase(password) {

    return /[a-z]/.test(password);
}


function hasUppercase(password) {

    return /[A-Z]/.test(password);
}


function hasDigit(password) {

    return /\d/.test(password);
}


function hasSpecial(password) {

    return /[^A-Za-z0-9]/.test(password);
}


// ========================================================
// NORMALIZATION
// ========================================================

function normalize(password) {

    return password
        .toLowerCase()
        .replace(/@/g, "a")
        .replace(/4/g, "a")
        .replace(/3/g, "e")
        .replace(/1/g, "i")
        .replace(/!/g, "i")
        .replace(/0/g, "o")
        .replace(/\$/g, "s")
        .replace(/5/g, "s")
        .replace(/7/g, "t")
        .replace(/[^a-z]/g, "");
}


// ========================================================
// LENGTH ANALYSIS
// ========================================================

function analyzeLength(password) {

    const length =
        password.length;

    let score;


    if (length < 8) {

        score =
            (length / 8) * 30;

    } else if (length < 12) {

        score =
            30 +
            ((length - 8) / 4) * 20;

    } else if (length < 16) {

        score =
            50 +
            ((length - 12) / 4) * 20;

    } else if (length < 20) {

        score =
            70 +
            ((length - 16) / 4) * 20;

    } else {

        score = 100;
    }


    return {
        length,
        score: Math.round(score)
    };
}


// ========================================================
// CHARACTER DIVERSITY
// ========================================================

function analyzeDiversity(password) {

    const categories = {

        lowercase:
            hasLowercase(password),

        uppercase:
            hasUppercase(password),

        number:
            hasDigit(password),

        special:
            hasSpecial(password)
    };


    const count =
        Object.values(categories)
            .filter(Boolean)
            .length;


    return {

        categories,

        count,

        score:
            Math.round(
                (count / 4) * 100
            )
    };
}


// ========================================================
// CHARACTER POOL
// ========================================================

function calculatePool(password) {

    let pool = 0;

    if (hasLowercase(password))
        pool += 26;

    if (hasUppercase(password))
        pool += 26;

    if (hasDigit(password))
        pool += 10;

    if (hasSpecial(password))
        pool += 32;

    return pool;
}


// ========================================================
// ENTROPY
// ========================================================

function analyzeEntropy(password) {

    if (!password.length) {

        return {
            entropy: 0,
            score: 0,
            pool: 0
        };
    }


    const pool =
        calculatePool(password);


    const entropy =
        password.length *
        Math.log2(pool);


    let score;


    if (entropy < 28) {

        score =
            (entropy / 28) * 20;

    } else if (entropy < 50) {

        score =
            20 +
            ((entropy - 28) / 22) * 25;

    } else if (entropy < 70) {

        score =
            45 +
            ((entropy - 50) / 20) * 25;

    } else if (entropy < 100) {

        score =
            70 +
            ((entropy - 70) / 30) * 30;

    } else {

        score = 100;
    }


    return {

        entropy:
            Number(
                entropy.toFixed(2)
            ),

        pool,

        score:
            Math.round(
                clamp(score, 0, 100)
            )
    };
}


// ========================================================
// CHARACTER DISTRIBUTION
// ========================================================

function analyzeDistribution(password) {

    if (!password.length) {

        return {
            score: 0,
            maxFrequency: 1,
            uniqueRatio: 0
        };
    }


    const frequency =
        new Map();


    for (const char of password) {

        frequency.set(
            char,
            (frequency.get(char) || 0) + 1
        );
    }


    let maxFrequency = 0;


    for (const count of frequency.values()) {

        maxFrequency =
            Math.max(
                maxFrequency,
                count / password.length
            );
    }


    const uniqueRatio =
        frequency.size /
        password.length;


    let score = 100;


    if (maxFrequency >= 0.70) {

        score = 5;

    } else if (maxFrequency >= 0.50) {

        score = 25;

    } else if (maxFrequency >= 0.35) {

        score = 50;

    } else if (maxFrequency >= 0.25) {

        score = 75;
    }


    if (uniqueRatio < 0.25) {

        score -= 25;

    } else if (uniqueRatio < 0.40) {

        score -= 10;
    }


    return {

        score:
            Math.round(
                clamp(score, 0, 100)
            ),

        maxFrequency:
            Number(
                maxFrequency.toFixed(2)
            ),

        uniqueRatio:
            Number(
                uniqueRatio.toFixed(2)
            )
    };
}


// ========================================================
// LEVENSHTEIN DISTANCE
// ========================================================

function levenshtein(a, b) {

    if (a === b)
        return 0;

    if (!a.length)
        return b.length;

    if (!b.length)
        return a.length;


    let previous =
        Array.from(
            { length: b.length + 1 },
            (_, i) => i
        );


    for (
        let i = 1;
        i <= a.length;
        i++
    ) {

        const current = [i];


        for (
            let j = 1;
            j <= b.length;
            j++
        ) {

            const insertion =
                current[j - 1] + 1;

            const deletion =
                previous[j] + 1;

            const replacement =
                previous[j - 1] +
                (
                    a[i - 1] === b[j - 1]
                        ? 0
                        : 1
                );


            current.push(
                Math.min(
                    insertion,
                    deletion,
                    replacement
                )
            );
        }


        previous = current;
    }


    return previous[b.length];
}


// ========================================================
// DICTIONARY ANALYSIS
// ========================================================

function analyzeDictionary(password) {

    const normalized =
        normalize(password);


    if (!normalized) {

        return {

            risk: 0,

            similarity: 0,

            matchedWord: null
        };
    }


    let highestSimilarity = 0;

    let matchedWord = null;


    for (
        const word
        of COMMON_PASSWORDS
    ) {

        if (
            Math.abs(
                word.length -
                normalized.length
            ) > 6
        ) {

            continue;
        }


        if (
            normalized.includes(word) ||
            word.includes(normalized)
        ) {

            highestSimilarity = 1;

            matchedWord = word;

            break;
        }


        const distance =
            levenshtein(
                normalized,
                word
            );


        const maxLength =
            Math.max(
                normalized.length,
                word.length
            );


        const similarity =
            1 -
            distance / maxLength;


        if (
            similarity >
            highestSimilarity
        ) {

            highestSimilarity =
                similarity;

            matchedWord =
                word;
        }
    }


    let risk = 0;


    if (highestSimilarity >= 0.90) {

        risk = 100;

    } else if (highestSimilarity >= 0.75) {

        risk = 70;

    } else if (highestSimilarity >= 0.60) {

        risk = 40;

    } else if (highestSimilarity >= 0.50) {

        risk = 20;
    }


    return {

        risk,

        similarity:
            Number(
                highestSimilarity.toFixed(2)
            ),

        matchedWord
    };
}


// ========================================================
// SEQUENCE ANALYSIS
// ========================================================

function analyzeSequence(password) {

    const value =
        password.toLowerCase();


    let longest = 1;

    let current = 1;

    let direction = 0;


    for (
        let i = 1;
        i < value.length;
        i++
    ) {

        const difference =
            value.charCodeAt(i) -
            value.charCodeAt(i - 1);


        if (
            difference === 1 ||
            difference === -1
        ) {

            const newDirection =
                difference > 0
                    ? 1
                    : -1;


            if (
                newDirection ===
                direction
            ) {

                current++;

            } else {

                current = 2;

                direction =
                    newDirection;
            }


            longest =
                Math.max(
                    longest,
                    current
                );

        } else {

            current = 1;

            direction = 0;
        }
    }


    let risk = 0;


    if (longest >= 7) {

        risk = 100;

    } else if (longest >= 5) {

        risk = 75;

    } else if (longest >= 4) {

        risk = 50;

    } else if (longest >= 3) {

        risk = 25;
    }


    return {
        longest,
        risk
    };
}


// ========================================================
// KEYBOARD PATTERN
// ========================================================

function analyzeKeyboard(password) {

    const value =
        password.toLowerCase();


    let risk = 0;

    let matched = null;


    for (
        const pattern
        of KEYBOARD_PATTERNS
    ) {

        if (
            value.includes(pattern)
        ) {

            const currentRisk =
                pattern.length >= 7
                    ? 100
                    : pattern.length >= 5
                        ? 75
                        : 50;


            if (
                currentRisk > risk
            ) {

                risk =
                    currentRisk;

                matched =
                    pattern;
            }
        }
    }


    return {
        risk,
        matched
    };
}


// ========================================================
// REPETITION
// ========================================================

function analyzeRepetition(password) {

    if (!password.length) {

        return {
            maxRun: 0,
            risk: 0
        };
    }


    let maxRun = 1;

    let currentRun = 1;


    for (
        let i = 1;
        i < password.length;
        i++
    ) {

        if (
            password[i] ===
            password[i - 1]
        ) {

            currentRun++;

            maxRun =
                Math.max(
                    maxRun,
                    currentRun
                );

        } else {

            currentRun = 1;
        }
    }


    let risk = 0;


    if (maxRun >= 7) {

        risk = 100;

    } else if (maxRun >= 5) {

        risk = 80;

    } else if (maxRun >= 4) {

        risk = 60;

    } else if (maxRun >= 3) {

        risk = 30;
    }


    return {
        maxRun,
        risk
    };
}


// ========================================================
// REPEATED BLOCK
// ========================================================

function analyzeRepeatedBlock(password) {

    const n =
        password.length;


    for (
        let size = 1;
        size <= Math.floor(n / 2);
        size++
    ) {

        if (
            n % size !== 0
        ) {

            continue;
        }


        const block =
            password.slice(
                0,
                size
            );


        const repetitions =
            n / size;


        if (
            repetitions < 3
        ) {

            continue;
        }


        let valid = true;


        for (
            let i = size;
            i < n;
            i += size
        ) {

            if (
                password.slice(
                    i,
                    i + size
                ) !== block
            ) {

                valid = false;

                break;
            }
        }


        if (valid) {

            return {

                risk:
                    repetitions >= 5
                        ? 100
                        : 75,

                block,

                repetitions
            };
        }
    }


    return {

        risk: 0,

        block: null,

        repetitions: 0
    };
}


// ========================================================
// PREDICTABILITY
// ========================================================

function analyzePredictability(password) {

    let risk = 0;

    const patterns = [];


    if (
        /^[A-Za-z]+[0-9]+$/
            .test(password)
    ) {

        risk += 30;

        patterns.push(
            "WORD + NUMBER"
        );
    }


    if (
        /^[A-Za-z]+[^A-Za-z0-9]+[0-9]+$/
            .test(password)
    ) {

        risk += 30;

        patterns.push(
            "WORD + SYMBOL + NUMBER"
        );
    }


    if (
        /(19|20)\d{2}/
            .test(password)
    ) {

        risk += 20;

        patterns.push(
            "YEAR"
        );
    }


    if (
        /\d{3,}$/
            .test(password)
    ) {

        risk += 20;

        patterns.push(
            "NUMERIC SUFFIX"
        );
    }


    return {

        risk:
            clamp(
                risk,
                0,
                100
            ),

        patterns
    };
}


// ========================================================
// LEETSPEAK
// ========================================================

function analyzeLeetspeak(password) {

    const substitutions =
        (
            password.match(
                /[@431!0$57]/g
            ) || []
        ).length;


    let risk = 0;


    if (
        substitutions >= 3
    ) {

        risk = 100;

    } else if (
        substitutions >= 2
    ) {

        risk = 70;

    } else if (
        substitutions === 1
    ) {

        risk = 30;
    }


    return {
        risk,
        substitutions
    };
}


// ========================================================
// USERNAME ANALYSIS
// ========================================================

function analyzeUsername(
    username,
    password
) {

    const user =
        username
            .trim()
            .toLowerCase();


    const pass =
        password
            .toLowerCase();


    if (!user) {

        return {
            contains: false,
            risk: 0
        };
    }


    const normalizedUser =
        normalize(user);


    const normalizedPassword =
        normalize(password);


    if (
        !normalizedUser.length
    ) {

        return {
            contains: false,
            risk: 0
        };
    }


    if (
        pass.includes(user) ||
        normalizedPassword.includes(
            normalizedUser
        )
    ) {

        return {
            contains: true,
            risk: 100
        };
    }


    return {
        contains: false,
        risk: 0
    };
}


// ========================================================
// CORRELATED RISK
//
// We don't simply add all penalties.
// Related weaknesses are grouped.
// ========================================================

function calculatePredictabilityRisk(a) {

    const risks = [

        a.dictionary.risk * 0.28,

        a.username.risk * 0.17,

        a.sequence.risk * 0.10,

        a.keyboard.risk * 0.10,

        a.repetition.risk * 0.12,

        a.repeatedBlock.risk * 0.08,

        a.predictability.risk * 0.10,

        a.leetspeak.risk * 0.05
    ];


    return Math.round(
        clamp(
            risks.reduce(
                (sum, value) =>
                    sum + value,
                0
            ),
            0,
            100
        )
    );
}


// ========================================================
// FINAL SCORE
// ========================================================

function calculateScore(a) {

    /*
    --------------------------------------------------------
    POSITIVE SECURITY CAPABILITY
    --------------------------------------------------------
    */

    const positiveScore =

        a.length.score * 0.25 +

        a.entropy.score * 0.20 +

        a.diversity.score * 0.15 +

        a.distribution.score * 0.10 +

        a.unpredictability * 0.30;


    let score =
        positiveScore;


    /*
    --------------------------------------------------------
    ADAPTIVE CAPS

    These prevent superficial complexity from cheating.
    --------------------------------------------------------
    */


    // Known/common password

    if (
        a.dictionary.risk >= 100
    ) {

        score =
            Math.min(
                score,
                20
            );
    }


    // Username present

    if (
        a.username.risk >= 100
    ) {

        score =
            Math.min(
                score,
                35
            );
    }


    // Extreme repetition

    if (
        a.repetition.risk >= 100
    ) {

        score =
            Math.min(
                score,
                25
            );
    }


    // Severe sequence

    if (
        a.sequence.risk >= 100
    ) {

        score =
            Math.min(
                score,
                35
            );
    }


    // Severe keyboard pattern

    if (
        a.keyboard.risk >= 100
    ) {

        score =
            Math.min(
                score,
                35
            );
    }


    // Very poor distribution

    if (
        a.distribution.score <= 10
    ) {

        score =
            Math.min(
                score,
                30
            );
    }


    // Length protection

    if (
        a.length.length < 8
    ) {

        score =
            Math.min(
                score,
                30
            );

    } else if (
        a.length.length < 12
    ) {

        score =
            Math.min(
                score,
                55
            );
    }


    return Math.round(
        clamp(
            score,
            0,
            100
        )
    );
}


// ========================================================
// CLASSIFICATION
// ========================================================

function getStrength(score) {

    for (
        const level
        of CONFIG.LEVELS
    ) {

        if (
            score >= level.min
        ) {

            return level.label;
        }
    }


    return "EXTREMELY WEAK";
}


// ========================================================
// FINDINGS
// ========================================================

function generateFindings(a) {

    const findings = [];


    if (
        a.length.length < 12
    ) {

        findings.push(
            "Password is shorter than the recommended 12+ characters."
        );
    }


    if (
        a.dictionary.risk >= 70
    ) {

        findings.push(
            "Password resembles a commonly used password."
        );
    }


    if (
        a.username.contains
    ) {

        findings.push(
            "Password contains or resembles the username."
        );
    }


    if (
        a.sequence.risk >= 50
    ) {

        findings.push(
            "Predictable character sequence detected."
        );
    }


    if (
        a.keyboard.risk >= 50
    ) {

        findings.push(
            "Common keyboard pattern detected."
        );
    }


    if (
        a.repetition.risk >= 50
    ) {

        findings.push(
            "Excessive repeated characters detected."
        );
    }


    if (
        a.repeatedBlock.risk >= 75
    ) {

        findings.push(
            "Repeated block pattern detected."
        );
    }


    if (
        a.predictability.risk >= 40
    ) {

        findings.push(
            "Predictable password structure detected."
        );
    }


    if (
        a.leetspeak.risk >= 70
    ) {

        findings.push(
            "Common character substitutions detected."
        );
    }


    if (
        a.distribution.score < 40
    ) {

        findings.push(
            "Character distribution is highly uneven."
        );
    }


    return findings;
}


// ========================================================
// RECOMMENDATIONS
// ========================================================

function generateRecommendations(
    a,
    score
) {

    const recommendations = [];


    if (
        a.length.length < 12
    ) {

        recommendations.push(
            "Increase the password length to at least 12 characters."
        );
    }


    if (
        a.diversity.count < 3
    ) {

        recommendations.push(
            "Use a wider variety of character types."
        );
    }


    if (
        a.dictionary.risk >= 50
    ) {

        recommendations.push(
            "Avoid common dictionary words and passwords."
        );
    }


    if (
        a.username.contains
    ) {

        recommendations.push(
            "Do not include your username or personal identifier."
        );
    }


    if (
        a.sequence.risk > 0
    ) {

        recommendations.push(
            "Avoid sequences such as 1234, 5678 or abcd."
        );
    }


    if (
        a.keyboard.risk > 0
    ) {

        recommendations.push(
            "Avoid keyboard patterns such as qwerty or asdf."
        );
    }


    if (
        a.repetition.risk > 0 ||
        a.repeatedBlock.risk > 0
    ) {

        recommendations.push(
            "Avoid repeated characters and repeated blocks."
        );
    }


    if (
        a.predictability.risk > 0
    ) {

        recommendations.push(
            "Avoid predictable structures such as word + number + year."
        );
    }


    if (
        a.leetspeak.risk > 0
    ) {

        recommendations.push(
            "Do not rely on simple substitutions such as @, 0, 1 or $."
        );
    }


    if (
        score >= 75 &&
        recommendations.length === 0
    ) {

        recommendations.push(
            "Strong result. Keep this password unique and enable multi-factor authentication."
        );
    }


    return recommendations;
}


// ========================================================
// UPDATE CHECK UI
// ========================================================

function updateCheck(
    element,
    valid
) {

    if (!element)
        return;


    const icon =
        element.querySelector(
            ".check-icon"
        );


    element.classList.remove(
        "valid",
        "invalid"
    );


    if (valid) {

        element.classList.add(
            "valid"
        );


        if (icon) {

            icon.textContent =
                "✓";
        }

    } else {

        element.classList.add(
            "invalid"
        );


        if (icon) {

            icon.textContent =
                "×";
        }
    }
}


// ========================================================
// UPDATE ALL CHECKS
// ========================================================

function updateChecks(
    password,
    username,
    analysis
) {

    updateCheck(
        checks.length,
        password.length >= 12
    );


    updateCheck(
        checks.uppercase,
        hasUppercase(password)
    );


    updateCheck(
        checks.lowercase,
        hasLowercase(password)
    );


    updateCheck(
        checks.number,
        hasDigit(password)
    );


    updateCheck(
        checks.special,
        hasSpecial(password)
    );


    updateCheck(
        checks.repeat,
        analysis.repetition.risk < 50
    );


    updateCheck(
        checks.sequence,
        analysis.sequence.risk < 50
    );


    updateCheck(
        checks.username,
        !analysis.username.contains
    );


    updateCheck(
        checks.common,
        analysis.dictionary.risk < 70
    );
}


// ========================================================
// STRENGTH BAR COLOR
// ========================================================

function getStrengthColor(score) {

    if (score < 20)
        return "#ff304f";

    if (score < 40)
        return "#ff304f";

    if (score < 60)
        return "#ff9d00";

    if (score < 75)
        return "#ffd000";

    if (score < 90)
        return "#00ff88";

    return "#00ffcc";
}


// ========================================================
// UPDATE STRENGTH UI
// ========================================================

function updateStrength(score) {

    const strength =
        getStrength(score);


    scoreText.textContent =
        score;


    strengthText.textContent =
        strength;


    strengthProgress.style.width =
        `${score}%`;


    const color =
        getStrengthColor(score);


    strengthProgress.style.background =
        color;


    strengthProgress.style.boxShadow =
        `0 0 12px ${color}`;


    scoreText.style.color =
        color;


    strengthText.style.color =
        color;
}


// ========================================================
// UPDATE RECOMMENDATIONS
// ========================================================

function updateRecommendations(
    recommendations,
    score
) {

    if (!recommendationBox)
        return;


    let icon = "🛡";


    if (score >= 90) {

        icon = "🟢";

    } else if (score >= 75) {

        icon = "🟢";

    } else if (score >= 60) {

        icon = "🟡";

    } else if (score >= 40) {

        icon = "🟠";

    } else {

        icon = "🔴";
    }


    recommendationBox.innerHTML = `

        <div class="recommendation-shield">
            ${icon}
        </div>

        <div class="recommendation-content">

            ${recommendations
                .map(
                    item => `
                        <p class="recommendation-item">
                            <span>›</span>
                            ${item}
                        </p>
                    `
                )
                .join("")
            }

        </div>
    `;
}


// ========================================================
// MAIN UI ANALYSIS
// ========================================================

function analyzeCurrentPassword() {

    const password =
        passwordInput.value;


    const username =
        usernameInput
            ? usernameInput.value
            : "";


    /*
        Empty state
    */

    if (!password) {

        scoreText.textContent =
            "0";


        strengthText.textContent =
            "—";


        strengthProgress.style.width =
            "0%";


        strengthProgress.style.background =
            "#ff304f";


        if (recommendationBox) {

            recommendationBox.innerHTML = `

                <div class="recommendation-shield">
                    🛡
                </div>

                <p>
                    Enter a password to receive
                    security recommendations.
                </p>
            `;
        }


        Object.values(checks)
            .forEach(
                element => {

                    if (!element)
                        return;

                    element.classList.remove(
                        "valid",
                        "invalid"
                    );

                    const icon =
                        element.querySelector(
                            ".check-icon"
                        );

                    if (icon) {

                        icon.textContent =
                            "○";
                    }
                }
            );


        return;
    }


    /*
        Run APSSA
    */

    const length =
        analyzeLength(password);


    const diversity =
        analyzeDiversity(password);


    const entropy =
        analyzeEntropy(password);


    const distribution =
        analyzeDistribution(password);


    const dictionary =
        analyzeDictionary(password);


    const sequence =
        analyzeSequence(password);


    const keyboard =
        analyzeKeyboard(password);


    const repetition =
        analyzeRepetition(password);


    const repeatedBlock =
        analyzeRepeatedBlock(password);


    const predictability =
        analyzePredictability(password);


    const leetspeak =
        analyzeLeetspeak(password);


    const usernameAnalysis =
        analyzeUsername(
            username,
            password
        );


    const analysis = {

        length,

        diversity,

        entropy,

        distribution,

        dictionary,

        sequence,

        keyboard,

        repetition,

        repeatedBlock,

        predictability,

        leetspeak,

        username:
            usernameAnalysis
    };


    /*
        Combined risk
    */

    const predictabilityRisk =
        calculatePredictabilityRisk(
            analysis
        );


    analysis.predictabilityRisk =
        predictabilityRisk;


    analysis.unpredictability =
        100 -
        predictabilityRisk;


    /*
        Final APSSA score
    */

    const score =
        calculateScore(
            analysis
        );


    /*
        Update UI
    */

    updateStrength(
        score
    );


    updateChecks(
        password,
        username,
        analysis
    );


    const findings =
        generateFindings(
            analysis
        );


    const recommendations =
        generateRecommendations(
            analysis,
            score
        );


    updateRecommendations(
        recommendations,
        score
    );


    /*
        Expose result for debugging
    */

    window.lastPasswordAnalysis = {

        algorithm:
            "APSSA",

        version:
            "1.0",

        score,

        strength:
            getStrength(score),

        entropy:
            entropy.entropy,

        findings,

        recommendations,

        analysis
    };


    /*
        Development console
        Remove before final submission if desired.
    */

    console.log(
        "APSSA RESULT:",
        window.lastPasswordAnalysis
    );
}


// ========================================================
// SHOW / HIDE PASSWORD
// ========================================================

if (togglePassword) {

    togglePassword.addEventListener(
        "click",
        () => {

            const isPassword =
                passwordInput.type ===
                "password";


            passwordInput.type =
                isPassword
                    ? "text"
                    : "password";


            togglePassword.textContent =
                isPassword
                    ? "HIDE"
                    : "SHOW";
        }
    );
}


// ========================================================
// REAL-TIME ANALYSIS
// ========================================================

if (passwordInput) {

    passwordInput.addEventListener(
        "input",
        analyzeCurrentPassword
    );
}


if (usernameInput) {

    usernameInput.addEventListener(
        "input",
        analyzeCurrentPassword
    );
}


// ========================================================
// SECURE RANDOM PASSWORD GENERATOR
//
// Uses crypto.getRandomValues()
// instead of Math.random().
// ========================================================

function generateSecurePassword(
    length = 20
) {

    const lowercase =
        "abcdefghijklmnopqrstuvwxyz";

    const uppercase =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const numbers =
        "0123456789";

    const symbols =
        "!@#$%^&*()-_=+[]{}?";

    const all =
        lowercase +
        uppercase +
        numbers +
        symbols;


    const required = [

        lowercase,

        uppercase,

        numbers,

        symbols
    ];


    const result = [];


    /*
        Guarantee character diversity.
    */

    for (
        const set of required
    ) {

        result.push(
            secureRandomCharacter(
                set
            )
        );
    }


    /*
        Fill remaining positions.
    */

    while (
        result.length < length
    ) {

        result.push(
            secureRandomCharacter(
                all
            )
        );
    }


    /*
        Cryptographically unbiased
        Fisher-Yates shuffle.
    */

    for (
        let i = result.length - 1;
        i > 0;
        i--
    ) {

        const j =
            secureRandomInt(
                i + 1
            );


        [
            result[i],
            result[j]
        ] =
        [
            result[j],
            result[i]
        ];
    }


    return result.join("");
}


// ========================================================
// SECURE RANDOM INTEGER
// ========================================================

function secureRandomInt(max) {

    const array =
        new Uint32Array(1);


    const range =
        Math.floor(
            0xFFFFFFFF / max
        ) * max;


    let random;


    do {

        crypto.getRandomValues(
            array
        );

        random =
            array[0];

    } while (
        random >= range
    );


    return random % max;
}


// ========================================================
// SECURE RANDOM CHARACTER
// ========================================================

function secureRandomCharacter(
    characters
) {

    const index =
        secureRandomInt(
            characters.length
        );


    return characters[index];
}


// ========================================================
// GENERATE BUTTON
// ========================================================

if (generateButton) {

    generateButton.addEventListener(
        "click",
        () => {

            const generated =
                generateSecurePassword(
                    20
                );


            passwordInput.value =
                generated;


            /*
                Immediately analyze.
            */

            analyzeCurrentPassword();


            /*
                Password is already visible
                because input remains type=password.
            */
        }
    );
}