// =========================================================
// PASSWORD STRENGTH ANALYZER
// =========================================================


// =========================================================
// GET HTML ELEMENTS
// =========================================================

const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");

const togglePassword =
    document.getElementById("togglePassword");

const strengthProgress =
    document.getElementById("strengthProgress");

const strengthText =
    document.getElementById("strengthText");

const scoreText =
    document.getElementById("scoreText");

const entropyText =
    document.getElementById("entropyText");

const crackTimeText =
    document.getElementById("crackTimeText");

const recommendationBox =
    document.getElementById("recommendationBox");

const generatePasswordButton =
    document.getElementById("generatePassword");


// =========================================================
// SECURITY CHECK ELEMENTS
// =========================================================

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


// =========================================================
// COMMON PASSWORD DATABASE
// =========================================================

const commonPasswords = [

    "password",
    "password1",
    "password123",
    "password123!",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",

    "qwerty",
    "qwerty123",
    "qwertyuiop",

    "admin",
    "admin123",
    "administrator",

    "letmein",
    "welcome",
    "welcome123",

    "iloveyou",
    "monkey",
    "dragon",
    "football",

    "abc123",
    "abc12345",

    "pass123",
    "pass1234",

    "test",
    "test123",

    "user",
    "user123",

    "root",
    "root123",

    "login",
    "changeme",

    "secret",
    "secret123",

    "000000",
    "111111",
    "222222",
    "333333",
    "444444",
    "555555",
    "666666",
    "777777",
    "888888",
    "999999"

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
// UPDATE SECURITY CHECK UI
// =========================================================

function updateCheck(element, passed) {

    if (!element) {
        return;
    }

    const icon =
        element.querySelector(".check-icon");


    if (passed) {

        element.classList.add("valid");

        element.classList.remove("invalid");

        if (icon) {
            icon.textContent = "✓";
        }

    } else {

        element.classList.add("invalid");

        element.classList.remove("valid");

        if (icon) {
            icon.textContent = "✗";
        }

    }

}


// =========================================================
// CHECK REPEATED CHARACTERS
// =========================================================

function hasNoExcessiveRepeats(password) {

    // Detect patterns such as:
    // aaa
    // 111
    // $$$
    // xxxx

    return !/(.)\1\1/.test(password);

}


// =========================================================
// CHECK SEQUENTIAL PATTERNS
// =========================================================

function hasNoSequence(password) {

    const value =
        password.toLowerCase();


    const sequences = [

        // Numbers
        "012",
        "123",
        "234",
        "345",
        "456",
        "567",
        "678",
        "789",

        // Reverse numbers
        "210",
        "321",
        "432",
        "543",
        "654",
        "765",
        "876",
        "987",

        // Letters
        "abc",
        "bcd",
        "cde",
        "def",
        "efg",
        "fgh",
        "ghi",
        "hij",
        "ijk",
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
        "xyz",

        // Reverse letters
        "cba",
        "dcb",
        "edc",
        "fed",
        "gfe",
        "hgf",
        "ihg",
        "jih",
        "kj i",
        "lkj",
        "mlk",
        "nml",
        "onm",
        "pon",
        "qpo",
        "srq",
        "tsr",
        "uts",
        "vut",
        "wvu",
        "zyx",

        // Keyboard patterns
        "qwe",
        "wer",
        "ert",
        "rty",
        "tyu",
        "yui",
        "uio",
        "iop",

        "asd",
        "sdf",
        "dfg",
        "fgh",
        "ghj",
        "hjk",
        "jkl",

        "zxc",
        "xcv",
        "cvb",
        "vbn",
        "bnm"

    ];


    for (const sequence of sequences) {

        if (value.includes(sequence)) {

            return false;

        }

    }


    return true;

}


// =========================================================
// CHECK USERNAME
// =========================================================

function doesNotContainUsername(
    password,
    username
) {

    if (!username || username.length < 3) {

        return true;

    }


    return !password
        .toLowerCase()
        .includes(
            username.toLowerCase()
        );

}


// =========================================================
// CHECK COMMON PASSWORD
// =========================================================

function isNotCommonPassword(password) {

    const value =
        password.toLowerCase();


    // Direct common-password match

    if (
        commonPasswords.includes(value)
    ) {

        return false;

    }


    // Detect common patterns

    const commonPatterns = [

        "password",
        "qwerty",
        "admin",
        "welcome",
        "letmein",
        "iloveyou",
        "football",
        "monkey",
        "dragon"

    ];


    for (
        const pattern of commonPatterns
    ) {

        if (
            value.includes(pattern)
        ) {

            return false;

        }

    }


    return true;

}


// =========================================================
// CHECK PREDICTABLE PASSWORD PATTERNS
// =========================================================

function hasPredictablePattern(password) {

    const value =
        password.toLowerCase();


    // Password + numbers
    if (
        /^password\d+!?$/.test(value)
    ) {

        return true;

    }


    // Word followed by simple numbers
    if (
        /^[a-z]+\d{1,4}$/.test(value)
    ) {

        return true;

    }


    // Common word + special + numbers

    if (
        /^(admin|welcome|qwerty|user|test|login)[!@#$%^&]*\d*$/.test(value)
    ) {

        return true;

    }


    return false;

}


// =========================================================
// CALCULATE ENTROPY
// =========================================================

function calculateEntropy(password) {

    if (
        !password ||
        password.length === 0
    ) {

        return 0;

    }


    let characterPool = 0;


    // Lowercase

    if (/[a-z]/.test(password)) {

        characterPool += 26;

    }


    // Uppercase

    if (/[A-Z]/.test(password)) {

        characterPool += 26;

    }


    // Numbers

    if (/[0-9]/.test(password)) {

        characterPool += 10;

    }


    // Special characters

    if (/[^A-Za-z0-9]/.test(password)) {

        characterPool += 32;

    }


    if (characterPool === 0) {

        return 0;

    }


    const entropy =
        password.length *
        Math.log2(characterPool);


    return Math.round(entropy);

}


// =========================================================
// ESTIMATED CRACK TIME
// =========================================================

function calculateCrackTime(entropy) {

    if (entropy <= 0) {

        return "—";

    }


    /*
        THEORETICAL ESTIMATE

        Assumption:
        10 billion guesses per second.

        Real-world cracking time varies depending
        on hashing algorithm, hardware, attack type,
        rate limiting and password reuse.
    */

    const guessesPerSecond =
        10_000_000_000;


    const possiblePasswords =
        Math.pow(2, entropy);


    const seconds =
        possiblePasswords /
        guessesPerSecond;


    if (seconds < 1) {

        return "Less than a second";

    }


    if (seconds < 60) {

        return (
            Math.round(seconds) +
            " seconds"
        );

    }


    if (seconds < 3600) {

        return (
            Math.round(
                seconds / 60
            ) +
            " minutes"
        );

    }


    if (seconds < 86400) {

        return (
            Math.round(
                seconds / 3600
            ) +
            " hours"
        );

    }


    if (seconds < 31536000) {

        return (
            Math.round(
                seconds / 86400
            ) +
            " days"
        );

    }


    if (seconds < 31536000000) {

        return (
            Math.round(
                seconds / 31536000
            ) +
            " years"
        );

    }


    if (seconds < 31536000000000) {

        return (
            Math.round(
                seconds / 31536000000
            ) +
            " thousand years"
        );

    }


    if (seconds < 31536000000000000) {

        return (
            Math.round(
                seconds / 31536000000000
            ) +
            " million years"
        );

    }


    return "Billions of years";

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


    // -----------------------------------------
    // LENGTH
    // -----------------------------------------

    if (password.length >= 8) {

        score += 15;

    }

    if (password.length >= 12) {

        score += 15;

    }

    if (password.length >= 16) {

        score += 10;

    }


    // -----------------------------------------
    // CHARACTER TYPES
    // -----------------------------------------

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


    // -----------------------------------------
    // SECURITY PATTERNS
    // -----------------------------------------

    if (results.repeat) {

        score += 5;

    }

    if (results.sequence) {

        score += 5;

    }

    if (results.username) {

        score += 5;

    }

    if (results.common) {

        score += 5;

    }


    // -----------------------------------------
    // PENALTIES
    // -----------------------------------------

    if (password.length < 8) {

        score -= 30;

    }


    if (!results.repeat) {

        score -= 15;

    }


    if (!results.sequence) {

        score -= 20;

    }


    if (!results.username) {

        score -= 20;

    }


    if (!results.common) {

        score -= 40;

    }


    // Predictable pattern penalty

    if (
        results.predictable
    ) {

        score -= 25;

    }


    // -----------------------------------------
    // VERY LONG PASSWORD BONUS
    // -----------------------------------------

    if (password.length >= 20) {

        score += 5;

    }


    // -----------------------------------------
    // LIMIT SCORE
    // -----------------------------------------

    score = Math.max(
        0,
        Math.min(
            100,
            score
        )
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


    // -----------------------------------------
    // LENGTH
    // -----------------------------------------

    if (password.length < 12) {

        recommendations.push(
            "Use at least 12 characters."
        );

    }


    // -----------------------------------------
    // UPPERCASE
    // -----------------------------------------

    if (!results.uppercase) {

        recommendations.push(
            "Add uppercase letters such as A-Z."
        );

    }


    // -----------------------------------------
    // LOWERCASE
    // -----------------------------------------

    if (!results.lowercase) {

        recommendations.push(
            "Add lowercase letters such as a-z."
        );

    }


    // -----------------------------------------
    // NUMBER
    // -----------------------------------------

    if (!results.number) {

        recommendations.push(
            "Add at least one number."
        );

    }


    // -----------------------------------------
    // SPECIAL CHARACTER
    // -----------------------------------------

    if (!results.special) {

        recommendations.push(
            "Add a special character such as !, @, # or $."
        );

    }


    // -----------------------------------------
    // REPEATED CHARACTERS
    // -----------------------------------------

    if (!results.repeat) {

        recommendations.push(
            "Avoid repeating the same character three or more times."
        );

    }


    // -----------------------------------------
    // SEQUENCES
    // -----------------------------------------

    if (!results.sequence) {

        recommendations.push(
            "Avoid sequences such as 123, abc or qwerty."
        );

    }


    // -----------------------------------------
    // USERNAME
    // -----------------------------------------

    if (!results.username) {

        recommendations.push(
            "Do not include your username in the password."
        );

    }


    // -----------------------------------------
    // COMMON PASSWORD
    // -----------------------------------------

    if (!results.common) {

        recommendations.push(
            "This password contains a commonly used pattern."
        );

    }


    // -----------------------------------------
    // PREDICTABLE PATTERN
    // -----------------------------------------

    if (results.predictable) {

        recommendations.push(
            "Avoid predictable patterns such as Password123!."
        );

    }


    // -----------------------------------------
    // EXCELLENT PASSWORD
    // -----------------------------------------

    if (
        recommendations.length === 0
    ) {

        recommendations.push(
            "Excellent! The password passes all current security checks."
        );

        recommendations.push(
            "Use a unique password and never reuse it across websites."
        );

    }


    return recommendations;

}


// =========================================================
// DISPLAY RECOMMENDATIONS
// =========================================================

function displayRecommendations(
    recommendations
) {

    recommendationBox.innerHTML = "";


    const shield =
        document.createElement("div");

    shield.className =
        "recommendation-shield";

    shield.textContent = "🛡";


    const list =
        document.createElement("ul");


    recommendations.forEach(
        recommendation => {

            const item =
                document.createElement("li");

            item.textContent =
                recommendation;

            list.appendChild(item);

        }
    );


    recommendationBox.appendChild(
        shield
    );

    recommendationBox.appendChild(
        list
    );

}


// =========================================================
// MAIN PASSWORD ANALYZER
// =========================================================

function analyzePassword() {

    const username =
        usernameInput.value.trim();

    const password =
        passwordInput.value;


    // -----------------------------------------
    // EMPTY PASSWORD
    // -----------------------------------------

    if (!password) {

        resetAnalyzer();

        return;

    }


    // -----------------------------------------
    // SECURITY CHECKS
    // -----------------------------------------

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
            hasNoExcessiveRepeats(password),

        sequence:
            hasNoSequence(password),

        username:
            doesNotContainUsername(
                password,
                username
            ),

        common:
            isNotCommonPassword(
                password
            ),

        predictable:
            hasPredictablePattern(
                password
            )

    };


    // -----------------------------------------
    // UPDATE CHECKS
    // -----------------------------------------

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


    // -----------------------------------------
    // SCORE
    // -----------------------------------------

    const score =
        calculateScore(
            password,
            username,
            results
        );


    // -----------------------------------------
    // STRENGTH
    // -----------------------------------------

    const strength =
        getStrength(score);


    // -----------------------------------------
    // ENTROPY
    // -----------------------------------------

    const entropy =
        calculateEntropy(password);


    // -----------------------------------------
    // CRACK TIME
    // -----------------------------------------

    const crackTime =
        calculateCrackTime(entropy);


    // -----------------------------------------
    // UPDATE SCORE
    // -----------------------------------------

    scoreText.textContent =
        score;


    // -----------------------------------------
    // UPDATE STRENGTH
    // -----------------------------------------

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


    // -----------------------------------------
    // UPDATE ENTROPY
    // -----------------------------------------

    entropyText.textContent =
        `${entropy} bits`;


    // -----------------------------------------
    // UPDATE CRACK TIME
    // -----------------------------------------

    crackTimeText.textContent =
        crackTime;


    // -----------------------------------------
    // RECOMMENDATIONS
    // -----------------------------------------

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

    // Score

    scoreText.textContent =
        "0";


    // Strength

    strengthText.textContent =
        "—";

    strengthText.style.color =
        "#19d9ff";


    // Strength bar

    strengthProgress.style.width =
        "0%";

    strengthProgress.style.background =
        "#ff304f";


    // Entropy

    entropyText.textContent =
        "0 bits";


    // Crack time

    crackTimeText.textContent =
        "—";


    // Reset checks

    Object.values(checks).forEach(
        check => {

            if (!check) {
                return;
            }

            check.classList.remove(
                "valid",
                "invalid"
            );


            const icon =
                check.querySelector(
                    ".check-icon"
                );


            if (icon) {

                icon.textContent =
                    "○";

            }

        }
    );


    // Reset recommendations

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


    // -----------------------------------------
    // Guarantee character types
    // -----------------------------------------

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


    // -----------------------------------------
    // Add remaining characters
    // -----------------------------------------

    while (
        password.length < 16
    ) {

        password +=
            allCharacters[
                Math.floor(
                    Math.random() *
                    allCharacters.length
                )
            ];

    }


    // -----------------------------------------
    // Shuffle
    // -----------------------------------------

    password =
        password
            .split("")
            .sort(
                () => Math.random() - 0.5
            )
            .join("");


    return password;

}


// =========================================================
// GENERATOR BUTTON
// =========================================================

generatePasswordButton.addEventListener(
    "click",
    () => {

        const generatedPassword =
            generateStrongPassword();


        passwordInput.value =
            generatedPassword;


        passwordInput.type =
            "text";


        togglePassword.textContent =
            "HIDE";


        analyzePassword();

    }
);


// =========================================================
// INITIAL STATE
// =========================================================

resetAnalyzer();
