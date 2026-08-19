// =========================================================
// PASSWORD STRENGTH ANALYZER
// =========================================================

// -------------------------
// Get HTML elements
// -------------------------

const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");

const togglePassword = document.getElementById("togglePassword");

const strengthProgress = document.getElementById("strengthProgress");
const strengthText = document.getElementById("strengthText");
const scoreText = document.getElementById("scoreText");

const recommendationBox =
    document.getElementById("recommendationBox");

const generatePasswordButton =
    document.getElementById("generatePassword");


// -------------------------
// Password checks
// -------------------------

const checks = {
    length: document.getElementById("lengthCheck"),
    uppercase: document.getElementById("uppercaseCheck"),
    lowercase: document.getElementById("lowercaseCheck"),
    number: document.getElementById("numberCheck"),
    special: document.getElementById("specialCheck"),
    repeat: document.getElementById("repeatCheck"),
    sequence: document.getElementById("sequenceCheck"),
    username: document.getElementById("usernameCheck"),
    common: document.getElementById("commonCheck")
};


// =========================================================
// COMMON PASSWORDS
// =========================================================

const commonPasswords = [
    "password",
    "password123",
    "123456",
    "123456789",
    "12345678",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "abc123",
    "password1",
    "pass123",
    "test123",
    "user123",
    "root",
    "login"
];


// =========================================================
// SHOW / HIDE PASSWORD
// =========================================================

togglePassword.addEventListener("click", () => {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";

        togglePassword.textContent = "HIDE";

    } else {

        passwordInput.type = "password";

        togglePassword.textContent = "SHOW";

    }

});


// =========================================================
// UPDATE CHECK UI
// =========================================================

function updateCheck(element, passed) {

    const icon = element.querySelector(".check-icon");

    if (passed) {

        element.classList.add("valid");
        element.classList.remove("invalid");

        icon.textContent = "✓";

    } else {

        element.classList.add("invalid");
        element.classList.remove("valid");

        icon.textContent = "✗";
    }
}


// =========================================================
// CHECK REPEATED CHARACTERS
// =========================================================

function hasExcessiveRepeats(password) {

    // Detect 3 or more identical characters together
    return !/(.)\1\1/.test(password);

}


// =========================================================
// CHECK SEQUENCES
// =========================================================

function hasNoSequence(password) {

    const lowerPassword = password.toLowerCase();

    const sequences = [
        "123",
        "234",
        "345",
        "456",
        "567",
        "678",
        "789",
        "890",

        "abc",
        "bcd",
        "cde",
        "def",
        "efg",
        "fgh",
        "ghi",
        "jkl",
        "klm",
        "lmn",
        "mno",
        "nop",
        "opq",
        "pqr",
        "qrs",
        "rst",
        "stu",
        "tuv",
        "uvw",
        "vwx",
        "wxy",
        "xyz"
    ];

    for (const sequence of sequences) {

        if (lowerPassword.includes(sequence)) {

            return false;

        }
    }

    return true;
}


// =========================================================
// CHECK USERNAME
// =========================================================

function doesNotContainUsername(password, username) {

    if (!username || username.length < 3) {

        return true;

    }

    return !password
        .toLowerCase()
        .includes(username.toLowerCase());

}


// =========================================================
// CHECK COMMON PASSWORD
// =========================================================

function isNotCommonPassword(password) {

    return !commonPasswords.includes(
        password.toLowerCase()
    );

}


// =========================================================
// CALCULATE SCORE
// =========================================================

function calculateScore(
    password,
    username,
    results
) {

    let score = 0;


    // -------------------------
    // Length
    // -------------------------

    if (password.length >= 8) {

        score += 10;

    }

    if (password.length >= 12) {

        score += 15;

    }

    if (password.length >= 16) {

        score += 10;

    }


    // -------------------------
    // Character types
    // -------------------------

    if (results.lowercase) {

        score += 10;

    }

    if (results.uppercase) {

        score += 10;

    }

    if (results.number) {

        score += 10;

    }

    if (results.special) {

        score += 10;

    }


    // -------------------------
    // Security patterns
    // -------------------------

    if (results.repeat) {

        score += 10;

    }

    if (results.sequence) {

        score += 10;

    }

    if (results.username) {

        score += 5;

    }

    if (results.common) {

        score += 10;

    }


    // -------------------------
    // Penalties
    // -------------------------

    if (password.length < 8) {

        score -= 30;

    }

    if (!results.repeat) {

        score -= 10;

    }

    if (!results.sequence) {

        score -= 15;

    }

    if (!results.username) {

        score -= 15;

    }

    if (!results.common) {

        score -= 50;

    }


    // Keep score between 0 and 100

    score = Math.max(
        0,
        Math.min(100, score)
    );


    return score;
}


// =========================================================
// DETERMINE STRENGTH
// =========================================================

function getStrength(score) {

    if (score < 30) {

        return {
            text: "VERY WEAK",
            color: "#ff304f"
        };

    }

    if (score < 50) {

        return {
            text: "WEAK",
            color: "#ff9d00"
        };

    }

    if (score < 70) {

        return {
            text: "MODERATE",
            color: "#ffd000"
        };

    }

    if (score < 85) {

        return {
            text: "STRONG",
            color: "#00ff88"
        };

    }

    return {
        text: "VERY STRONG",
        color: "#00ffcc"
    };

}


// =========================================================
// GENERATE RECOMMENDATIONS
// =========================================================

function generateRecommendations(
    password,
    username,
    results
) {

    const recommendations = [];


    if (!password) {

        return [
            "Enter a password to begin the security analysis."
        ];

    }


    // Length

    if (password.length < 12) {

        recommendations.push(
            "Use at least 12 characters for better security."
        );

    }


    // Uppercase

    if (!results.uppercase) {

        recommendations.push(
            "Add at least one uppercase letter (A-Z)."
        );

    }


    // Lowercase

    if (!results.lowercase) {

        recommendations.push(
            "Add lowercase letters (a-z)."
        );

    }


    // Number

    if (!results.number) {

        recommendations.push(
            "Add at least one number."
        );

    }


    // Special character

    if (!results.special) {

        recommendations.push(
            "Add a special character such as !, @, # or $."
        );

    }


    // Repetition

    if (!results.repeat) {

        recommendations.push(
            "Avoid repeating the same character multiple times."
        );

    }


    // Sequence

    if (!results.sequence) {

        recommendations.push(
            "Avoid predictable sequences such as 123 or abc."
        );

    }


    // Username

    if (!results.username) {

        recommendations.push(
            "Do not include your username in your password."
        );

    }


    // Common password

    if (!results.common) {

        recommendations.push(
            "This is a commonly used password. Choose something unique."
        );

    }


    // If everything is good

    if (recommendations.length === 0) {

        recommendations.push(
            "Excellent! Your password passes all current security checks."
        );

        recommendations.push(
            "For maximum security, use a unique password generated by a password manager."
        );

    }


    return recommendations;

}


// =========================================================
// DISPLAY RECOMMENDATIONS
// =========================================================

function displayRecommendations(recommendations) {

    recommendationBox.innerHTML = "";


    // Shield icon

    const shield = document.createElement("div");

    shield.className = "recommendation-shield";

    shield.textContent = "🛡";


    // List

    const list = document.createElement("ul");

    recommendations.forEach(
        recommendation => {

            const item = document.createElement("li");

            item.textContent = recommendation;

            list.appendChild(item);

        }
    );


    recommendationBox.appendChild(shield);

    recommendationBox.appendChild(list);

}


// =========================================================
// MAIN ANALYZER
// =========================================================

function analyzePassword() {

    const username =
        usernameInput.value.trim();

    const password =
        passwordInput.value;


    // Empty password

    if (!password) {

        resetAnalyzer();

        return;

    }


    // -------------------------
    // Perform checks
    // -------------------------

    const results = {

        length:
            password.length >= 12,

        uppercase:
            /[A-Z]/.test(password),

        lowercase:
            /[a-z]/.test(password),

        number:
            /[0-9]/.test(password),

        special:
            /[^A-Za-z0-9]/.test(password),

        repeat:
            hasExcessiveRepeats(password),

        sequence:
            hasNoSequence(password),

        username:
            doesNotContainUsername(
                password,
                username
            ),

        common:
            isNotCommonPassword(password)

    };


    // -------------------------
    // Update checks
    // -------------------------

    updateCheck(
        checks.length,
        results.length
    );

    updateCheck(
        checks.uppercase,
        results.uppercase
    );

    updateCheck(
        checks.lowercase,
        results.lowercase
    );

    updateCheck(
        checks.number,
        results.number
    );

    updateCheck(
        checks.special,
        results.special
    );

    updateCheck(
        checks.repeat,
        results.repeat
    );

    updateCheck(
        checks.sequence,
        results.sequence
    );

    updateCheck(
        checks.username,
        results.username
    );

    updateCheck(
        checks.common,
        results.common
    );


    // -------------------------
    // Calculate score
    // -------------------------

    const score = calculateScore(
        password,
        username,
        results
    );


    // -------------------------
    // Get strength
    // -------------------------

    const strength =
        getStrength(score);


    // -------------------------
    // Update score
    // -------------------------

    scoreText.textContent = score;


    // -------------------------
    // Update strength
    // -------------------------

    strengthText.textContent =
        strength.text;

    strengthText.style.color =
        strength.color;

    strengthProgress.style.width =
        `${score}%`;

    strengthProgress.style.background =
        strength.color;

    strengthProgress.style.color =
        strength.color;


    // -------------------------
    // Recommendations
    // -------------------------

    const recommendations =
        generateRecommendations(
            password,
            username,
            results
        );


    displayRecommendations(
        recommendations
    );

}


// =========================================================
// RESET ANALYZER
// =========================================================

function resetAnalyzer() {

    scoreText.textContent = "0";

    strengthText.textContent = "—";

    strengthText.style.color =
        "#19d9ff";

    strengthProgress.style.width =
        "0%";

    strengthProgress.style.background =
        "#ff304f";


    // Reset all checks

    Object.values(checks).forEach(check => {

        check.classList.remove(
            "valid",
            "invalid"
        );

        const icon =
            check.querySelector(".check-icon");

        icon.textContent = "○";

    });


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


// =========================================================
// EVENT LISTENERS
// =========================================================

passwordInput.addEventListener(
    "input",
    analyzePassword
);


usernameInput.addEventListener(
    "input",
    analyzePassword
);


// =========================================================
// STRONG PASSWORD GENERATOR
// =========================================================

function generateStrongPassword() {

    const uppercase =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const lowercase =
        "abcdefghijklmnopqrstuvwxyz";

    const numbers =
        "0123456789";

    const special =
        "!@#$%^&*()_+-=[]{}";

    const allCharacters =
        uppercase +
        lowercase +
        numbers +
        special;


    let password = "";


    // Guarantee character diversity

    password +=
        uppercase[
            Math.floor(
                Math.random() *
                uppercase.length
            )
        ];

    password +=
        lowercase[
            Math.floor(
                Math.random() *
                lowercase.length
            )
        ];

    password +=
        numbers[
            Math.floor(
                Math.random() *
                numbers.length
            )
        ];

    password +=
        special[
            Math.floor(
                Math.random() *
                special.length
            )
        ];


    // Add remaining characters

    while (password.length < 16) {

        password +=
            allCharacters[
                Math.floor(
                    Math.random() *
                    allCharacters.length
                )
            ];

    }


    // Shuffle password

    password =
        password
            .split("")
            .sort(() => Math.random() - 0.5)
            .join("");


    return password;

}


// =========================================================
// GENERATOR BUTTON
// =========================================================

generatePasswordButton.addEventListener(
    "click",
    () => {

        const generated =
            generateStrongPassword();


        // Put generated password
        // into password field

        passwordInput.value =
            generated;


        // Analyze it

        analyzePassword();


        // Show password

        passwordInput.type =
            "text";

        togglePassword.textContent =
            "HIDE";

    }
);