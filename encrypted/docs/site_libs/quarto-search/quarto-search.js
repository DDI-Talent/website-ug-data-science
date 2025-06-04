<!DOCTYPE html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Protected Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #ffffff;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #4CAF50;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #4CAF50;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                background: #76B852;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Protected Page</p>
                        <p></p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Remember me
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="DECRYPT" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
 * Initialize the staticrypt module, that exposes functions callbable by the password_template.
 *
 * @param {{
 *  staticryptEncryptedMsgUniqueVariableName: string,
 *  isRememberEnabled: boolean,
 *  rememberDurationInDays: number,
 *  staticryptSaltUniqueVariableName: string,
 * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
 *
 * @param {{
 *  rememberExpirationKey: string,
 *  rememberPassphraseKey: string,
 *  replaceHtmlCallback: function,
 *  clearLocalStorageCallback: function,
 * }} templateConfig - object of data that can be configured by a custom password_template.
 */
function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
            const templateError = "Bad password!",
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"f47318c5fd3803ae193d62be64fc11e2c8309738daaa647d23c41dfa787dddd4621d2b1d021f761ce99e6ff4dccf9fa2188b683f5f2a162369e0c83994a10ce71197034ee7769979ee416f66cb96fb9ee7836c89e1d8683c3be99732c7cca7eb274f525b74a4c861acdd8186c6f8d86c8c1cc80c6447c3c2be17638b2484903a9b402f461efee545a64d2daabd44ec324497724025148bccc16109a82e74bee8cdb70196f58c8ed0a1650a45c875367f3a331607daccb3fc72e86ec83883a65a865ed19daa9b5eafaf158127f9d658beb1d22be909a25f26f4bec45ebabecb8bfe56e852cbfecb13033b2b9b104007ad78475188ca3a27c5aa58921f8df498a1f7f1ba7753e8bbb9822de09adb6961c4b7b4c572c6931a4ec1f9123dbad1ebe7653958560b30012b79cde32c26cc9c73f858da0d3588c8fe3c3814302e5b3729208781634fce6a3b0c0e1a0b11bb8d539b508102dc77b043617831086a00870f07a72c437aa96692a3d17d13f9f3801817cf333a7d0e947a46ba4ebb88802f7fe08724b565a8e5bad416af7bbfca8ee5ff3bd6f7767580bd39e93dcdb92b744966acffc859ea8643acdc7aabc06da53b8b14b7c886e94bcc10f427b170f06bc3c2fa74f85c3b01949f998f331370384345b910b4c90e4181ce101f64c3c8d53fe61928a0c6340635c77b66619802ccc1acd1cb1a7688d45d8d0024e73bce4db26f21a66f6e5f4f098ea9ab4809973278458ea15fba233d84f5743ae0bc9143dbbd55b1626953c173d2b12f761879af5783af9e1084152b44ba1720b19a0eef37bc0417eaff9e8fd888cb3a7e1255ea544c9e6766f0109176c7a0e9acc57635fcda4e469cd8f34486e3ead84c8d13415107d81f51cedc5bf07803397f1673d509406b9baf64b55c534c32673226d62e646d10f853ba53cb166c8e8103ff09fce7e9eb0b8ad91b3ab68f79348747a423aa55c5a7b14945b2bc3fad5051b3b7324588e960d0dac932737f7104df091e80e44bc7ad136f28949c119b2c53128f5801f0504f910deb8e7cab48414daafc74c764b66a4bcc920bfb4b3f504ff471bbf3b8b4df10a1746d158fc967bf5818e63d911ca7232f5e85a52e6822b71cd1bb124e2957b02c480ea3fe89fb63f705d057310dae899196f7d3b0539d7cc79a9158c5ebf49bdb0dfae7373c514ab5067ac0f145a2e76be006a16b61ee45014505f217b3a87db5829c1b77e3ce8e5b9ed6e8f165898264e4f323be0c222c49d63d6a53692825f8618f899d5f9470bab76b4aa02ed3eb46a77813630a787857f1a5e62cc8eb5c0b91fca15eaa1fefb4fe5f50a70fa71b576ac8f3738c5388fa368deeb884b382f68267a7816699512d4b6f7fc2b23c8058cc0926d97efbb252a471a643843802e209479bcbf4d3591cd659a0fde5aeadaccb396674c32b90e8037fa8a36cbaefb523c5a03bc2b65401e6cbfd26ce4b0768850178963494facfe8fa338f63949a5c3e5fee5cfeeabf0f00348fe89a04807897d6bb3e6c53dce1f3215a855bfc9e62252e1421a4488b537020a9934a95ab19341c54e9e61aa1f2269548d1de55568dfccac0b972e1e91b1cb2e37f406ead2b64b1ac163b0a39b18aaa2deb2e59b41329b2490c170ea253a6f76fd14785503e9b0aee4507d636cfb8e655cd513144494d5086fda5a97d68914da239958ad9e8e85af915e3bea5fe885853d14260733295d18913b36f4e8f0648c80f615735d3be0ed4aafe3199bfea94dcaa0d7f8a28e27d7155e76de448bd7ba76b884b50767a1d42a49e5efe07b09da8d9d162b3889cce72a2b13b49eca838cf899dfd7e7c3105d73f340e42dbabbca53646ef409b950a97e630b41fe94cf10b3d11502781b225a413bb9ca81d043b9c92ec36762e737dd3a9c0517d0769f089f7cbfbeea7c04f1a40520f58fcf0dac52a124d37871703bfe67af9cf5869a0c2c778ca8eb6f94939fc54f77de28ebb2b1db2be44d8c7e31665cbc6bb0d99cd6fbfce9830d5680c3482a28f96459ed8442ede531c3d9ec89ab6db5b30601264d1e0fa422666e7a4f5fe2bde4a7b294c418faaa546757c36bf69fa78231d93cf83d9138c019fc6ca12c7b5cf25cab73c11163450b6a7147cc7770ab58fd8ed27568b2b23b3d354166ba799448512bec2063b5383ff099cb6377e619ab84bb579a094561842c578170a5e5a4fcd7bdf822561cb7d69bdbe848dd00e34103f056d5f095e6ffb95e99650c0b5d7689834a845605249c8c6e6b9bebdba562d7fb33d121c797cdb17030561ae2e2fcef308110735eb3ba26f24cb210e65ddb5275764d627403da87153e0f72d0609a213c71c32b1163759a12f4b1f9a2ad51880b401e71f983a0f5fa8988e63e2cf811aa2e738199e8d08d5882b24d9406795f0a3238dcdf999d607f31f30ebd525319e6c2c79acb9110680cbbae514bf066f71330d222cf2b82bf8c820fca3e880b8110e094454bc59405f405fc50a24bf50ee26c522beee14585ce93179f51a4015229b447e68f6f85a9f5a85dd49c8c08c90a27c3a7927541ba3fdaa3e33957c0320a03837b7decc47de7b365cb11c3e0397b306be38048cb979db6ba2f3768e8b22d9681c0e3e01d28f071c9b38ac3eebd18969c025a5b73d8ae690cb87fa35bc1390f1a5ef3acf1ecc7c13c0461bb3f4cc99de93bd121d98a1b231caf7dfb901c8cd76d63047738b087902908835028d9495bd6049ed3c48a5f2d816704267d209b57a9eb5d1906f838248b15ad7eb353249ed58bff676fe42c627d64e83b7101b54d0d2f17192b57422940eaa99769a9578fe41c58abdf48d061355c13532b4294e2e3e107c7fe00d0e4fe1c81beb908b460af43c23ba5fcb57bed9a40fafc93fc351288d46385244c22f9b5b3106ce8d5fa4af38cb84b0a61b3ef4e358d7f15f46aad338618f05b31cfb29c4dbccdb2e49952fbdce9763656440d17418f338ccdc3314458a29d7f6e52c3cdfaadfc9cc35cab261f1cc503f824a46119dce51b8d14d9062810871ed2d7397ed4c44a4642764f3255821c93f2e06f9de600e3f44f00ff84898cebb862b2e9ee12f56ba4d3410925da394df101dd2ab49d7773da8e7222ab983ee874aeb58cbed50108ebf79f56b470466381a369949e4bea464cb1d3a7e5b7481f58d0e7ff33c224f3461ee7409b2a336b871e94e64f7a1d57ccafd67e8214bda974799df34ced248ad98adac9b6b3daf42a8c944e8ad8ad2091bbc8a94fe52284d6385eab594b17112ef468c664de8ed219b11e72ca8ca1fc75e547fc3bb0b5e79149f147c91109cf602dbaee6cc2beaef765b196c7e391012ce163c340884cb012a7ba7b0f2f5bc43686a3a48955acf9d11eb345c061ba2c13f9f87e3391383f8e624917747346d7e93e9c829706419ea730f2807f43f5a0dccb67da4016300d0e3dccf82a763442e7a04082fc61df9104eaa4360ef42aaf4c748828dd7885b5d14ff302fe6414d48b63998c332d844f253532d511a969ec39eefe0f05777170d7e5a7128446a9cf779bcd8a1f9e6af3ff016b5f6b16a6e5ac38f70175fc9648981c3303336046db0f0094f7f2df9b8f8b38bd6d159680147c8d01bc6f77d7009fb738cf39cffcd6eef3dc2a1804c682af96c4a40e370919fb42910c99aa2854fdf8239a3eaf2cde100980cd0267c4db0993255b7f90da668de44e9eb336dd11be464f508667496df30a7e188070c9087a4dbe02c804c19ef9af68ed118a69818c10e92f3c77522c36e6481aaff1fb954b16f65871d9ab4930ef4b26339bae9dbff6184ec4017082433f8d14266f0ea16ac977703ec3ff7dd3d35fd880eab42e08162ac2ee090d9afd76f2e76fcf206ca3b4eb2eb440561113318becf6d4158afcfb6773590b84b2a567a3f5b16a970b1471286b85e59fd10a483260650b17be2aee4b37e7b2d30cd70c1bb03b7ee28573f49c65706b5428b7bb6eba884e87d27ba613ee0e480f9117e0d91242f638a97cd89896110a38ec469e1cdfccdd01806fc8aa39c89679817e62f33419b6ed327ed57a0146f6b2b4408b601f51b5180fe5df9cb469ce68c3a87b52c15ffdc631f3fb409b834aa41225f0447a5a6154f8215eabcfda0f9cb2d31fee339df6ce9fa5bd40dc76175555726497136d0318aa0394a3d1f7ef55d64219bbeae09b709ecd49c7d67d7b4c99e5bb559f072a349189fdd84981d2f299fc837ea59232dc2c9eb7172980c27c5a255ef7341199a1dd3277b1dbeb6596e6a25296872160594e133d5891d95adcc012be7a1fa5a906e6b7fb5f1a83657f5d2b05dd7c9a55d870dea6fcf4432dcd166f154e43a38efc18bffff5c2ef39f821b6d67f1885786d84df9aaef382fcfb0273a18c6000b35e4ecd8d4662c28db2e99611c10c48ebe1cdbd1c3123ab8f39fc979de2d60539e4e3496ac2abc4537decc24de0840f888f783a2757e79714d3ea10b1bf50f194a0f3d74db7405ed06f1104314c36e33d001aeb3d5716f2b78ebba8bc009bc249c6077e6621e68265aa1080e5330a85f00891daabffe41b546fe4099632594957294aae2c03c2894ca3efe58b1fb77638c52fae28bf9687fa42ac637a77b31a1bca8547afeb0ad4e1e574e64c88b7a62f02877230dc357a0be322d9f2a9ce3076f3fedb9208169a08804cd7b978e81e6d0a28b960085367c4da1021be6443c766a6e0421a65eab216aa64296a3e1d71fe6349bafa11fd7b41b03c8b21102480a0997da42d7c55b9a71106acd0fa63dfd49c29f25eb662308f3fab5a669b6fad3bae294d95dd4b6466cdaf85f55e5ede9f85332d523beb7eec9d4f887af5ff0f8575bb9c5184fdfcb04d023ccd45767adae338635b8ffe760916d50e2a6bcdbe2ae0417b083321b51a28d20819bcdbacd51232291221b66aaad6406b3f9b2ff7c25a556040fe1d3ea0444349b2909ba21988eca85917b9be6d259185edd18965f82408455cce2673149e0f78cf6b4da5dee3019fc9a5eb31ea826031af6df9f8dbb55f6d8aa5cb7d3a16e6061fdba722f95db94adbfcd159b2f9f4e7c2710bf1fc495734bb4b67c77fda63a913f62f7783b5a8bd16afda53347b2c530b8fe35f5a0e9f658511e165ac9769a0440b35dcd7f2c2f0b89e37e5c0f09c60e39886718813df0e10ca71eea9155d419d11e3cc02fa2d68dc94aaf9092e893859b68c04d649bd3d18b66b095c05dbe392859e40ae23481207724841d05fd7f9f3a479d8265fa3d96ca8204863da1584d6d60ae975782781943a5068fe0fc24c50d9831d483f95f28bb420dc9e9ff9504231963ed046dc785ced8386a598accd23c96696cea8e468c72d19c906799b805c8790b6c2f726646b67b9ca5876799b47cc2f44816e59a00a3d1ad7bd9d46e5c42b81a41be3f4eca9e3454b903922a2ea47220b1a0864c046022424a5ad035b73d54a84a35333c3be67f47ca66bbd7020e4f2bbb051b1bed297f747c4f6307df9b4e156bc7fe5b074fc34801a4929a35270250780fdce9cdf4501ac8cfbb8ddb7ab58e1ac90ef64478d70ea9519b15d2d424d267a7685577de61af14c8e48704ec3ca72db15cfff51773c23773cc4cad8745a0a4d782ad1f209b47da7b7ea7572378f07b6a10a73e32a104713982483c48a9f565395f7a30e2b9b36ab5418150e4dc346b22c4b22d29cc22c41648fa121d5dadab6e2405b10eeb99f960fdb5fea9b6edcbc584f3a7c8aee76925ba29e1365659c05bdfa2463b24639f3631febc99a3328121e70b61b660181b63455892b259e73f932b1851ab3233f73d7ba9488d247aff8f6c3f5ebc7f7a1a8ae783a8391f5a644deb56f8954084ac3449912b7ec5e3225a4f156346917db851820d33893444fbbf9cc87293050d419f37cf0da54297c55d93a086d4a223599728ae4c955ddda7123c64a53f6b462a130382aa72c3fd6987cb6c82babb09b0dd5c57db8244d652ed50f8d7ea3cde31a925eed0fd2e3b778993be77768bf8368df0633ff8b6e8da7147ee4d20d210cc8dea8ccd8e81129e99cd6f622c225326ffcb09613296f07e65cbb76773f1082245a9f6e84113d84e0b375125cd51b3d45ddc1f2659febddc2e0373d02f3a871f0980893d9f3314e6578469ea7e06a435568ef15a2025fbc909c9fef4cf7a4c4c8e6f713509b19081f9dfba837f82e64a2e7e278615a05c069ad4bc70542f556ff6b0f6f1acd827306941634c23983e900769ac24d912adad0fc6be66f7c50b827f21552a69850738484f5c847eb471aa87acddc141dbbb762bef402f07be6f1355691bf6bf46ce4e519fa93a0209bafb747d486801d74a6ab14c95a7b1a936495e7db2f9b2e425165eb7df97f1fce7296a546e924e4e535455be3b87f7ada2e93573edf5fc54df8a530fe123a6b4f6203ba09ef7100171d50ef5bfc90e819296a84f414422c94cddeb461d1b230e785ca13dca8b6e94b8e4c8e91fa42b7de3b5a323fbe69d3f0697e6bacb280af2ef198e7388461a89f0c93dbecb96e4664020c24a060e9ca9c7a545af100271c245b504fb911aec612d3a497ac869f5b22b0e99fef4d5b59b72c2e1ca1ff43e3b3edd6bd7ce9a586d0e0a6a08d2d839355a57a974da4809427095668df4d156a98885a7d8b464e84655be5490e0733fe978bf134ddf2cc9181573097d171fe7469f246618020ed21ce663f0e232a08dbd06a98004ac66ed50449ea7a54f81a4cf3986b982ebba5300da1eb38f5a4a8fdf20d667f32db1a520a004d7f19e72966932502baea943efcf0939920a1abde0bafdf92c4270381cf3de4f8937703de8da295c3dc8dc84539e78ba3f555474196ca0fee9caf6b0f4c9187b64ba81be9a9e510f2ae77ff251c533ca41767bd838b8fb68817b9b553b58964201b53f0667af7b645336d178685ec88900124c59767a8d4415b2e74c4a6c34224cd546664ae86f9fcc6a5b42f6b1cd0a053293fea843f238c3a8dc035bd65dfa98789413afefa97ea5a03f12b894e24ce43ce73025c3acdfebd4eef0e59f7255d6e05053261cc04307f00ae3358954d54c83c08cff53f82aa3ee751200d7020b52fcba79ea667a0b5bd2a2cb3d6f948225c353af5512d500ada60b6ed24126def955622ba5af742ba85953fe39639f48d84a3a5f701ddc557d9618f77a26b3c7ef5b8fbaf27ae79aeb9edad27a845ef461843bb7091dced10fd1b963e59d00e58ea29701ecbc8d76948d6ca8ef3f64a9e4a28497d0a9ffd228165b1342eaa16fe5f10b3d044927c563a4362b136b2de05118ed85289fae3d3babf2a82309faf96e5c86fd1fa0b6219d7ddb7da9a53c4f5157c3e1f8ae7de90f160e9fbd2e7fa9112d1fba3f7ed62ecb9e459b5cb56dcbe9157522f073d116063fbf287a747047831542406703a01042d6e7299cf137fe21fa4079d6fe530904dbc89461639456a40b8a842a0fd35c61b7342f4ae15d0c77834b17da7d92f02db08dcd583c02efc143b55ab0a8f048fb0d02384cf856e6cb7965a3e9f8a8fbb2881c27051db8e9e53ce7f9ab541ab1d4a042888f639a2b5037dc8927f759884fb7ae5a8d65afdce46faa1e85a748a3e70509c15708fe859236b7ce383b88d5970aa86b2bceec141c80360e1327b13dc2c0329e1473bdc186d2d778e342728ca902cb6ebfa46e76e0db64cabd3170bf20ddee346688d1e2c1c4b2af944e95ec0243fd7d3c7f6c441dc96197a7260287b9c63f5db1f21661a2a8a8bb8182a12f3863f7d21bbb51b3579cafc146dfc9f9f089539a4597daf9a7ad3dc83d58bf66697396b7e638764f8766f54ef2a52aa4ba721f251b46ac023e265858b88af64e986b151a33fa99c1a870ba4c27ab7d05619af8174645f604361e40897a558baa9cf74d9eb0119b4c0c2127b4282de4783a1c75d3bce4f24409191d549113a69a1501d3e13e4504ebdf50474433a16388551e897454d2e6011d209973890244fe29055ed51ee79e07c7cf6fdb22b00c879bdd351361d82a9e14c2fcadef0a0bf95756acef7aa4780ae954e352b62d279b35d3f951f0d07355b3b6c716c13459f602c435d6e246f1f5c3a9207065bd128770a29ce5520db63ed3f1d2aec7408038247db6d308107f1dac0b9e161c98282a2bf6605ad6aac97ba02add3241d558123f6c966c640db26c816bfdaefbb65824632c26e34c0e16af68e757b36152b747e9665a7fde3e2456ecc2d72b63e219c1e77b26beeb847b4e5e6c60600dcc8852c07a2e49ed3abce660dccb5d659bd5e0cdacefadb71b6b62bb82d0b64f2f0c3f20df2e14bb33d944817aa1c8ebaecfb2be6b173215eb550b25b3719ee1994831cb3247f2e7212a1d05e3757ba935de1072b1da08ad4d0e7d0dc8011eff9b3d62929bb77565dbb8ef23e997d6cd5d83378b0189919fc52126bc1da233340c0014e6399de180e3f4064cebf3db15fbce3be9c21437f4c564b735df5512477075f672aabb451d35c4972ca7e696a2f795f7cbfde190acc11b3bbbaeef33666bdc86c785b6cec32c52621b0c0432d9de96b6fe09497f33a78cdde31fbedaba7b1680cb8ecb743424426dde2ea692c89c8a5ca79016565f2fd5f307d2d616ce3ce705a336df88757d947b02bbd11846434239d457b1b3255b87ebcf2624e50b18d6d69a0f5cbec0525b854b49364dfefa87519fb871aa7e5a19c5b10f5af68aa97ab2f4b3822701e84e431d5383f78d75347457336e27a12e4effd427e1e9ef497337129a72f3362fd49a7e64b4689e90fe17f0bd1ad61c34d39e999e41e5e0a77274e635cb72588b1f6bcc6007d63c175f9d3426642267696b716b0c634421c1585f1830f597d3f8d893e3d6ecae4cd42f4dd77218e6ecb92d07031905a7544f8f42f768654540d50776534531076b6c808f05d97230655adb69c2ce4eb6aeb755d9c536d2be2cc9d1793be21fabc0a2daf128d955335295b9cc9c6931100c1ffcf494c0199d296f904827153379fd8a9ac3c9f8e8f0272a8bae2be5db01c14f7382ac725e18766a28432606fcc475631a9529169cb9f307212c97cf5d35333e15dfe50a6e35b17e8e950bc586d8fa6cf33fd289fcdb17d3ada983424577a921ac2f1607633e14e3820b05f221ce84c5e6bf040054e067f65b3a09b516dc26f8847ca0222bc43461b7fa9f6f71a182f94fa370f2219e2b08c1d3d0abac48922daf03507ffaebe81ee6097dd4a1f86be37f44721b180209d266e717c21e58c87df4dc5b60f7a0f58a9b748e77df816f4c97bb316313e0a93b1e534e139caaa1c6234829f9a577c7102277d31cb31b5b84a176beba0f916f69d1b272ae4373cf6da1d5ca4bf57be7a77aaac064d13a417d5554ca4544d043e3bd288c6d8c18f4418f04b2c3cf1a09fda864be3112b503afb1e12e24625814a7c1e5b12f6de18b34ef1ca5f5e6f49dff0eaa48cc0467985a220e69f3626e27af8680538ad1e06caae4b438fe7ddb978c8070b9c625ed241ad68a58a6d30dfad0e5832b5f1d9b4314836d8fe9a0a8e7abfa78e93020e6541fac15710775ea7ab673d1c588bff1a3a28b4d246c74d1ce5eff343dbe91a4ec29cc994955715405b70413a798e87098895ceae2939cbdc37f6d22b5e3d1697e42da160cff199a05590bc0200603991b879ecaf068fec97fdadc1e75e6d795dbd74009e5aef67a1c609b2e0be2afe9eb0e0432dd28bb3f779d88e1bd9e8a8335f61a68d6631d990bbce43caa7aa8dbe1a81dbbed17bef1b5a201d682c51e2b160e19e4fc967e5564eea98254a2569a4dde931490971da6233caf503d9fa3b6d74c083a730396805f3de8bc3603188d899d16f58af75b2ef580c79c4879febfe8e13072308b689ec9cf2295da84d8c0b02c5725665aad84c72ca607653220dd00a31a5b2e941fceb095d0f4f0e709beabb81bd7c24325450a9581fef6f9841ce6fb5fd470114fce6ea9c7bcd72279350ad600ba337b43337b1d1a5223aabba0625f71eca751bbe642d4fd8a7bc9846fc59b0610a7575659ae6814c6ee9186e45fa37372f34c94b3a8e89d14ef0be1a1fa23ed46bfc47f8933f8285161afcfa93c8aa899c181107a282f94f21fdf5c6f78551d9337848a1a00ec4c828e1a3dfa17bfb41ef6efe92dbe5c270938798d654b5d159b04a10f2da67a41fcc63f8719b7a78123e3bc6a9d3153c0de42bc9e9055f5a62f726e47461d0feb92d58626293865753f1ff81de29da1376839f5a9ec35a1cc013f66b34a03d4c291d0cd36187cc52d43689b31438bfecad4f50b8928aec4117038f1168c632ec9bdb143fc8a5610be0769ce9aa2e877f3303754af5c103a23b00137e8607d5d87431205772affe368bdd5ee350c23be72ee905b53a604e589c35c113d3a046f227e38141b2e4f458fc29b54e6e763c192bdd7b0b84bf67fae1b28aea4dcc6e41d8e0409be7182cba98e9b9fafbc3f4b7f7b04104c529afc401f55ed3be4daf81378f798732eea7afd48e38f0b7304fab7a94b60a0a37078b253595bb028b00fdd4b1b396611d651b77f24f5a9e17a716dcf437327f5006e65ee2a670667269a507712cd4ac00f56a1dbb0748937ec4fb4bd944e84757e64c6311effdc11d5e75bf03c2b905e1c62aef5d5b54eb07e86ff60795827ef9d490b74baa9696ac0514e14bac6f235f97118616bfc87ffd107647e84496e8d8d2d7882e134eb699d7bc918de44b18a834aa6e9032d373cf07ea330cd4aa0c246130a36aed18bae33ab1d3278ebd983dadbcf75333f02dc70fdb10a31838298d00627263c0cc6accbd3e015711daa032f0b8d6de5df42ca2ba72d7d92175190b1e88c25f7d742fda3b5cf9dcdc7756676e8f29c2ae09f8328fed2b95ccecf9742de2d4cbf851a6b9784288ee8fe667aa8e33d61f28219073f5fa16a53b2d77760a1839aac838ad2a9dc991872bf2c5c9962e69d21951d721c3e74cf061ae22e82cca968ab92d9447ddefecfc286ddc527a4e9f34da4cbaa5d2851f90790798ca86ee3e93ec89dbeb89523982da3710fde86891ef9f40603460b063d8102edb6d2968f3975f983a4dd49526c06f6daf78cfa0f4399ce7beeedfc5ccbaac2666ef49d051e5de58b6e2ae8db0b6a9575d1d8bb8c0c27975ed81686d1e1d480e66dd76c3b60077ca25eeb1dacb5d85c5e256a08199f08933c5fe654c2c6f2696a358093c2066719d0c9dc218d7f167ce71743d1e4557669b900d523671156c220a91f21bf28ffdfad89ef63e6fec72804319f08f5356d5c309edd3b162e9ad45c527af6b347ea586be7d7c46ba6de21741f53bbba315dacbb7a498c348daa0135953114a959b7c1caa1fc0770fa3d373789657d248090ec6aad045c20d695a04b2467f2d2863840561ff3953a3921fb4d0ae1c792931ba6eb4584ac5e164d03e6f36104ed56576072e911ce02b9d01f4d6431fdc74475902c225cd03f6557e0bd40f4d1d2002f3cfb6f952816e0289ad63eafd4620a4c5edf04a776bc66a5b6a67f5f26cea940e983180f99fe142e58c1f0c1840548e8afdf93c21431bf6b2163defc40d332a69209e94a91dedc482c38d9eb40e7bc18dd948c87d24f60e2bf5e5a5facbad1bb198c2b87b1d953dcb30cc1719b620ff62531c52b3f6b8d9082875d3b0c0e28636b8b17d686d188993b0f378e3c7b08887b12646d98452deb0ef3bd9707ee0b45ac51a0027cb105485036112433d58003b5edcc2b0c937eb5a41295ce18a9ad9d4ee3dac0be7f16ea1f51c74f94e115e374922dee37af6512815b8c2164292e56bc475f942fbb00cbd2a54137a9b6b46469fe754b603d5c3d29dc93ca2a80825914d5df0dd504ee061c06c77eb2f7f5dcf09396a823b7f77c8033e64daf30424dbc41e199e4fb895c3fa1d6355d81d57e08bfd146c7c2e9cb40012b54566c20b9003635d1b7b05f9c749211b3be355fa0f67b82c3a0a75b134ef1f0ccc2cf5ca2712b3f53e8276785ac68912022596fa43350ab4691afdad25002f64d817963f33df003ab13f9a027b398ce783db6f04c9efca7d72241aa7de1ccb3c0e52be0245e23fbe0ba34599c363f2ea3669459d8815f3beed7d2706eb823f2ac375520376d232ea46ccc3620c8797ff1011445dcce32e0cf3a28affc9c3fcf7c23e3989114f1bad5dee68ed2e7c990394a6f0f1a6c63be722ae77642d9d60e6cd41570b5ec46b612b998076d86516f345ff05bb408d0966bf4c0242f7039249da2ae4d6a3a1c517ac51b5d08b7cb8f88bcf529c86892bae14c24c69df7178873bab20ec7565e4be5bf4b0280a8abdba42e3b218d37165877a6a9c437521bdd9529eaf68dd46dd598af77ef221b240c11315baeb129e4f7f779d39e7f14a37588ebe6a667427178a65fe87540d1bc263a1d403a13def0ee01bdc7502556806f742dc4c4a1e74289e91148b2231a4d337844c043623bed31082a6300d721a1e7f4ef0f3f0c21a371d8a61623303360eb1f14b6b855a18236ef242815c9aa71f92f2c92183c03729ac857c4d7957278f7845512cfbc937e6ec0905a71c306facbb3351be0e05697fac4121344994e13732ff2373ccbd52bbe011bdb7085fe5d5a62c6b0cdc912db2447f0c9d7aad471335142cc16b45f3c32cb631c3530e6f3ccb946c27658c24fd5dceca757fdf35d837b8f5e84f40952b5c1c2fcd0adab31621bccb897bdbdeeec0d97a53877c1ce5abbf7bb68c09fceafcec46332e791062475d20d43d6902e7f03d3b8bdd12e8eeaee4ea1ac6d833bf07aac6518c4242d1cade24212aea16869d09951e017655ba42f98a561b42a84f92d292918b909a3343567b271987062a22c5c7473c2ae1d92ed03da294c6c9795dabe343b3da2beeb9d7468d1dce0f168f762e6af33009840d5a6fd2701ae8f12790ab5efe341455b17f482ea16de8290c24d0047e060963c6b0b57a7aad34c27add58ac03855d1b0c59474f601cee9d99669bb2d34975662407393edb5c0ea7a3c592b89939f422637b79639e19542ebedfd76382fa31c83a7a03e9c45fb31b9922d2d7401320a9f98e3d719efc3420fd9cad08305793d229ce7c47f8ce9f9da527ece87a573d17c847771386c723c4854fe1967f906f1735bcf912bc311d845dee5c7d5a9535e4317948050a4d4b3f50351744c0986407069dc889347757c38aba726955a43178d6d05b55ae95cd49ad2dd323e0645a75b0a2aef8a7be048ede731bf77d80e39fc7bd6d105fb5365ffe75bd573260b0465e21049f13e50083913f64365456ac5ba966452ca1c80470b5f9e808891e70faf6b37db360de9beed4c74324ac553397b9f0a394d448a27ec728eb1cb60cf54fbc3ddb0d6524546e36b62ad0ad5b96757bde5d6f8b62b402ced87b208ace5907bc9533fc60cb22b3bee2c5a21bb3df4f43f086db83b247e2225a70f111233d99ac3a26c320ec890392f64dc79ec9f73a89bb21c8b667c419376c6d7fbbb6371b4dd42c1ad8c5175b3eee2f87d4fa2117f0a98dfd7f31140c89e5a57586a9be891fc6b6d1d576166cb5da6da42bb12e39ef8dcaa8e4ae69d1ea44e156d6b47e6bc3d62d53c428bbddc1249018aa87951d2409246a1023bfd1ab663bb37f879401adeaca2b7495a8a0ecdda37c42d3deeec6588084cc9b11c3e737a4c22476ed169a8324a99bc24e6c1e43be49f2f78db125a5e57d13e8ed684c30aed4b776676a47b0b7a977e9dcd41aaeac0b1bda0ef94a0da68af3d3ea151d4dac1cd40132fc5beb6dd069678998fd87dddee2adc4dd47a396ccb3952ede314a0cf6a75cfbcd3fcebaec4326f9dd53548a6b5dffe8c0770f5a67d969b5acf6ce81808dafdfebfcb7775745ec11b0d2ca09afc658d54a0fcdb1fac5e036387cc100a64611955cc6f07124c7e498dd86ca2ad2333a94fa831d262f98cf0522fdbf1470d250b09ae93b7c2298723cc04ced8de46057438a48cc0a3fd9a9c9e989e2a983eadb94438c143f19f90a8761ab46030e26a779be7aa65661cc2e3da79d74576599e6992135fd3601761bc48c9b504e7d46426eaa1d56f652534088a9758b6386a9aaf3da922f458926f76957babb162f8661e02172e9c8f113d315968fe4b104684ee317177b8c8ebedde39ba313f335b63ef9367e156c46e73929e02ccb1d5738a0643919c0ce998bf8f0fb840b0c162f1b716159db85457666b12ebab0ee395f276ffc89df46635e24e439a876ff6e672b4dd560776db3dfcdfb235874811be6a2aa5540c59e3835abe70e4ec155a2aab8aa8cbadbfc7e8ead7522115ce6bd3af423dff61a74fe25f740d845ed2deb14f1be599cc30fb456781deac212b3c0073a76bf12e9a7f0fcca222374af56a915ec3c95f6e5bc09299db628d6c6e72d84d5c65f36cbddbe5ed7939644bfd45552a913e2539914bd84db1bfbbdd2b4d618731e09fc252ef2bdc36137318da19c385f22a332a7993ddefc3055a48f56108ad9e0f801c6bcdcc0cdc68f16344836676926daa89693aad292032304a4bb5ecec6ac2d48917026bc32d92c60796c456f7e21214332f3660f950a521a42ea52e5d67edd1da774b4f72c1992a3d2d72e8cbf7f459317a358becf498323ba02df9bc2cc5fb768c4dc47b31f197fc89da796d41a4a60e84e0bf54a23266b2039129099e33f729df9ac194d3b21cb5bc6ba57883160ecbe0cccffec65a0968f19799ad9c97bc1a6164b584a507537da57472d23e9bb877ba75241f16f2b5c89972d3b6018539c0794b8a97cf62fdeb2471f4f7c6ac1ccb50c4edf83df727eadbfb9abc25505560894e46737a5a27078b739f35b96b3efa5fb0232b173a85a94374f53a866afe23d05920408493862693547634908e7e27cc3036c694c0607ab536ecae619759b999904e08d2875f604110fe25f9d7371fe62cf01929e2ede492284049519033a0d790fed7b34aae7b168856e7f1a0dafcc1010ac04f699066002d4d0d7ee744ad2578c802f1606247c1d7a602ba07e9356df7074a695e5a39eab4d92816d765ca96132b9279c30b8226a4c35ee9f92c7d75325f66c2bf4d90073487eb311dd82570cb621e74a8e2c825b83fd64eaeece00ce674996456920d63ae6ec5e384b28da5d26d3cdd039eb258e6c0a68d09f52b0cef7f75ca336e08806fa15fb460e3b2020e1a086e2dd3eaccc276c876a9457a1260131a841de393f68483585f6f8e9d422f4e99d10ec39921d789b790b0a51134d86261cde8feaa5e71429a1bef734e2359a1800b636112662c1217e6bdedb05b9637aff14f2b39fc177328a34b7c4a5372fb21a6454b17c419a1d509c6ca6cda63e6a878b825465fb6f8c62a699af546034c3fcabd28a881f6559ffd4a274007c43d5e3cbcdcf37939bb5637d8352fb97f3cd6983cb23adfe6875fa675622ee2e715e274b76353a2cb845bb8a451e6a531329249646fdfc260203fd0492702bfed86b1ffcfaacc73d35443d619a7704d70bb01e7ac4cad0a543ae7a679a527c5515da0494fd451423873b5fd0084e38da113adc99ce0d5dbdcf71f7460bc895cdb276c10cd4939807ab6622c03354d00d7ed8955633fb055896c9585287f08699e585c49200114a9872e2b0d4c5f7463fbdc059c64ee66b9dea1365834c62e9183dbcfb5fb196aa2cc430182c793c57c12cd49e4a807f120b4ee250ee4652537afbff8cd07ca0cc44d00469b0de6bc1657d8439326a2ee4b4e790fa3d00f6521560379af98c33ecfe16aa7f30536f3a51da28003646393b8e2a776eaabb69f12db3273bc032db0913181e2113e329f791f819a3c0e19a570460bd5191e05d88fa2dc15cc21416b7e3c167e8da468daf8853bea4060a9d39df44318372eece4dc1b47ec97bd45dfe5bbd525e780c7cc95fd8b69834a8f6b3e4cdbdf1f8e597dbb07cb2bf828cd76d5ce767e0e6a70c37ceb766bc4c7427dfab91bf641e6fc09a60b53c4e8f35ad3b7787184e188d61a7b43080a91fee83aa7cca92428a69879b4f7d6acf69518d4e84a8999db44d28d985ce96fa2427bc65c6e2707151b805e7f407622ad0acf37ff98949071297e78595efb495590f1286c440f14579c6edb292006e1786787cf0822585e8683f403defd2ab91415d305926763c3888298c5eb74aa968a01c67506756d4a887f13dedf53e351d2092136b7aa1eee1bfdb105d54ed602eea15d8833a06f74485ecf4ffea288bcca0dd28196c0d2e231e64ee4c6b3aacf738f05434121f39e19467742cfb0c4f75afd74039045d918cd7dc210f6ae3e95e62baf699dcc1b368a2756f7ca703c38a7f7fd9008766d8eda5890a3e1a32396d01478ec76882550955f0edf666d58b66697ac97ca163561218d6ba977a653b6a2a358f21b3e054ce8b82d8ffe2571e5c44e909d73532c7195b7ae46a66b040d8b8a5d9b8bd5ed52891027c4ba2af5d5f4cc19f00997502567c8c22924fce607cf7738bd80242a721c582c7e65fa64f498a6f4e50b6fae2770c331244de466f1ec1041aaf5c7dd390183717d12bfbacb0b4132ae1c5422ac6d996638ec5bdd63e88aee9f6c24f201c7b62f2470aa80fb97f8804a8136d8ee9158d90aee09460e31431bffe92d7862931664f50839b497ea87d4ab4e2cf58cb3623e73fa20ebb56ee3647f84ee1eaccb69df9e137cda94b8434106a4118912b3792a81e785867fef8d597f38100dc444b010e602d6c8d6ab235152195a19ecdd15439b839c8587529e881e81b8c68c6bccd84776a2ae78a2b1e8885cff728a8fac56ae59e066e033175ea3f0bf2a5b87577298ef060cddcbbbdd36031d3301dd3779b437004066f8c3cc70f7017ba2ee882157e0084ce3ba6fee222fd16767b84665c51be89b83ff5548d5441681696f8d2e617a85767309d2fa0e7141294b6c065e14e27373ffcac8b148e6006c51bbc656b00d87cdd26349327e97053f45e9c17cc2dbbabaea9402b3e302f947c28ce5b30837b405eccae4e5a52ec377dca3075039dffd2c9e9c498dfdff12dacc8c719793ea7336869340f7f42fa1d41cf6f439129d13147a9c493853d81240cfc56fc171744326b3f98f7f5f1bcf331db4cf4f55a8d118b4732201c77c9931b5829f265de6f1974aa3d1405136e6c78cf72c82526e169f33fc637dc4d16cc07f4948a4bdb0e1cd42d28e06149470659c9eae80d5373af272bde457ea7fd63d75bfa5201bfcbd0e3b8a16bd88d5c0f046cf9ede55dbb6f1cb80cadb176dfec40bc166199e54b55cb624df6e8ff47e9a42ef797c2c3f0fe9c6ab3a5b1895a83bf24497b848b272b468c62d49dc1281c7a28bd2423c16b9b6eb8125a16d38d7444bb4d2259db914b6b9af35f559381ed8bbed6d28c12c57db31c7958dc8de4356a2368b1cd4923282910e2926271d34fb8a3fdeeefd1f98c809f8a90383491741cc0d00d454a75c13742c2feacc5eb6bd0b8f16d131f045292168e35c8741ae5ad7bebbbe4da762cc6d0258e8f4c0d59f3faaa8dec5bac2305a3eb463b4ecc361d4022802877a15089a8c9c2631225196c3933be66e9bdb973d4c8e3149b979e35767efdcf3ac9684a35f7aac65bed00174ff158c399e4a4ac316ea6c199691da1101d1adbbaf2dbb994748c04e169566fdfbf188bd2eb9af5de8891cec929c76ddfff9192d02f91d3ff7700bbe59c26e53a48f9e721072cd5c44a3ee9f53230665ce0a82c018af28c18d548a7c04240f242220c825fdfebd46ba21012cb85c2d682a6382a1a787d9777f8d46624d60dc8f76974213a7abdf39e540141e991fb30c3e70d23ba2d674199179f67cc03ab7099e0c68c88cd7fa22f907fe3a0d31a377e515467a1d7f4ade39a212892c8fcea45f2198a2d4687b3b8681f4ffdccf6ff2595c2e1b2ce9a1e3557d82c3ca63f54446cbc266856923d8e939fd516d7dc952061a63aab5960fd9babe60a433ec10050503dc4ee4798cf9c8f919ca89b1c8169e9ed173c38628bfbc1b76593f9267f452fdff14875990e23481437bd8bcbf9a781214bf47b16af14e0e93c293fa34377d797ded8a98b8f4d47d696690b5850796bb225596764b8e3e423b81db2bad135b6b98616d595d21cead247af3aea8b89c7f7b5f48e79e3ad843c8ed8bd20151acd065b8d1ae048eca13130b2e41ad808017d26e3468ee65667e4bb4f11003d57bc0b7446a9029999418df1ae4ad2743752fcd930d9e95f777192e37209597bd796db3d9c2cfb2b6df4e5dab0e0927b632c84c2d4e92f6084e92b618d19df10dc617c89495703d7d403a2a785e26e0ad4fb2d97e60feed3a9888e3e91493a12333df5a7bbacf527f74145a4f8ed0e40a9b7469195cc7a07e67fc282405659d3c41e58310360b1b3daf5ccf628b654d8c6f94fe2c47ebc8c67f07dc2585a979a05aeb8005b424c51f5b3a8e7066c16bd5266fd6ed2ab376fd0bd428ad2fb6b9602939ab2638c1cb0c514547a9426628a87c1fba42a363a4d9a61014ee6109d328a5adb9c402a9510f96ac3a66990fd189c8146917a125a38783147ed5420061fe6e10c2d62c4231649eb7bd9b2223673d71574cef7b21638530406d02e44f5de22b0f50ef8f9eb4c44b4a582647f03adc04ec46260597380c7cd3e7ebb347fac657d49c8e4f60225ce8575126732306a748a97664d8d1663e4df2be35e7f9b591df2bc5883415212eaa0ae82c315ba05345d1e9e63f963c440b8ef52370c7f54b05a7cd9fd2b4a9badf360e538ba2da47fc013ffc1a1480c5b583744bbef81b88c52e389cde552126c2bfdf286523f456716c3fe719a30302e7efabe9694609aa6e64439d7a479934609ef2ec3cd4e9f1a09700a8ae765dc65a37d5a3008d22aa69360c23498f22eef1782e361d11f4a9244027f6f9a460f18e96edd24c3f086cd9a8a9415d34b8514978ff17f289008c4a73d142cdad06c9d4b50609adac15da5490eeefecebc58ba4bf7d0b2253b6acd166ba6f21e5278ff03872aa05de0a18839de84600057ba62240f027432f2d66eb3ceca07f557b234ad30914acb9da1e8a7e6e75cc9a8faa79dc9a0d6e4f06c7c3131ea174ccf603cb85e2cf2374bda7a6ecfacccd4d16c9321d765adec1509628f72d73fcf3ea8809a974795c935bb164004301c99bb7155ef03b7424c5dbe3d2607790d891357bd6bcf396feb413cf4c4cd140e644cfa39fe31e1dc2f5490fd9e17a23ab52056e99d2968b3fad264ae6ba7bbf4f57f97685844f2232840d7dbff94190e0a7df8c5bc2f83feeb1945bbf42408f7f8f39acc361a2aa8cbae5e1129f5072d3c481170472113040921bb99f2c9f27222136d39c5466802d44cfd0932b1f22ba474e9e4c97121b05f89f00d890adfe039499406c02ec69ae5569a65a421ce3b7785310ac68692c94833090fedb8e8aa680aeecd916e7cb2fe20e9f431246793ee3b65a0b37c6e214658ee87b99fd2fc3ecad37cb3cfd9ed35bbd1325cd2188416a7d852eaadf1de220ecf2f1b1087dea93d8bcc16bde3a685674573af8248f72464b26205bb9929bbef6751960644b6504e3620cb50c9fa5f6ca8aadd8fcf780dd89f0c0e8b91cc5102821b77a6bb01da1d316ecb7dad09c1a60a430c203bb13eca71ab0fb8759d3b04c247378ab15caca04ed3dc1d27223698c966f4d125afe29a3f2bed44aa26cd92e8b2bf1721398f425d36474697ce7450af3ddac7e6ab98cc5337a2d0bba2c4758640caa6ca083e2a3778c1b4926c3551ee95437e553ee4a8a8ff9c7e70c9ffd57f402e27d2bb177a2ab63860c25ab520c60db4b3e7baadf2c7e9226b7e2e3579f0294182737085f40979b62a3cdf154becfac5586d79769bfa2fdd6ae5eef48d70926dd68fbc41a68ffd3d08dab97d63db763e2082552da2757c971c6c8232629b918f051713b2bf91029f608c63706f2105b196c85e74008827825985a5807ea47a5465074631b3b3f09cb0c2ca02c58b115796426f8ca96e64ae2259c7b6b158bae12a7cfc33290424934c337b39cebdf944272d89ee3115fb4fc4ae5eb50dc19f0737f7955779f8adbdfe1aa395995e752f4acdf6b3828015b57270a29fdc3bc400cc87de9b9fe0f000219cc648a3c092bb8d9e7ac778f7c5343a312c3a6e69b3650267c052e16f1531b5b7b98cdcc6be05002ee01ab0507b8908e01c42e1638d7f9ee2a39248ba3fe36af52806a9305f602c7526e8f25a106ef24395e98e820637e189dc9ed337356ff4560bce01ba448c0ffbf2f066b4d1ed9fdcc4f9cffe7c308b8a0c8879849484f858f4bd0cef9b1ab4271d60cde59f8566d43fc7e72a25ea66e7a9fc1a57bd70964cc22defd889a03e43b3ed41bb4e176154ed1372285bce854f16a7d01147d827c5883ee9db66911f81152fe5596881d3f4a14f95b5f02eebfc765e14839e2f7f109b896171a7d5bebd53f218348c026055ad6d08a7b5630ccc0e52c273ed3739a36584d5337be973c1540dc8ad910cccb5c5d6cbd9c9e08ce7c1a864d1afad69a2c2cb35f7ffe6e7d0368eb0127ae70316e9e5e146887b730cc7b31ae863ed2853e4f64ea00a5f8efa64bd149251262b9099ab06a510d6457a315a80e8871f21d9f8b3b97ae68001625cd27f7e5c6cdc33cc4a0cb02b31938053a507d0f47517a91c8402f0b9351cb059daa08f1260c570095a82d2aae5a8dfce312593a7cac913195b32846be3058614ad33444a298abdc8ec02aa5e51fc987191c7967e99a2850c7268f71d818d16292763ecff67e10c82b0bac2eac61df855830cb496b008299e73e4a47ac9feb963b6c98cb460ebdc96e6e8554269f452c4b8e62013a90a4b135ca35770654cf221d132e49905a3112f4913910a281b6a74f10316f639230ff536c8ddc22e5f7d8e61c0bc73f09ff45f68aee0ea49592ce10c7202735b88aa0be01f1d83c8b19ddc423ac3ff4725d9a16516ce156135cecd2f4579bd63ef79d9f6e576d41d6d4dde52ad698f80e4b52b2124f68cb33cfd85f8f62421e876e4f435742d7aafa9e1c259301b5be53803dad9d5195daaa77826bf472aaba76a8b7bb4dc05a9ef5577cd48763f45f0eab1dd254e8fe6744a0a498c32dbe570629d2371deda0fb8d2f70c090ae81d16df0b34a829ca8c15f240fc9066150e27307f0d6b2a4942794c6723d73fd88291d5cd460703ba1b565a5c94d49ee91738949f45a63303c86f39e54817e67255b4e0bcb5dc955263068b4de2bf56b72fbfd68878b0064161546d17d793d57c70dd3fc5d13b885b223167f261ca124f34faaa1eb12140bd1013184c89e2e16ac237a572df7858c8d2fb01b7ad5bfca734c31590c155335f3a50e7dcf942f3a3f0e56074b946f7a2bd5881fde93bfe395c79ce99cb42f8e1f9dd74fa6ef1a7a3ee06d45b554fb893170733bf3bdeef0005357632e101668326a2d77cb03acdbb37794d7bb24196f5293b238fc06ad3f573b50c9ca2b92825cfbe57ba607bd0437510193cd16b303e21647c1065de8d5b2193c65032bba150095f9afcb0137aaaaa1bd5d1913d638070a6a0153cbfa4218f392776b05b1eae3cfa66037927302b509b5c67674710816855a25b4e54b0c0daff932a166877fd32ac0b08e26eb991c24a6d71a02a972075486449c3834016db4ed2155e031ee7805e8583a8299497fa511a7c21ed6841fd76e477bb74b0141eaea7fe750c5770025d65420c3728965c6b9b5dd976b355e26569a77b6ded71d5210bf8d9c4c295c9ffcc0a448336d02d734519ecd70a6cf2ccf451551d4673183fdfea1bbe65596781e878074b5de5a4523fd3947c5fee48dc94f22ff0b8aec00803febf307a2546c51288e728ce1c0b6399d4330dd11aa8259c4510b04dcfbc93e2385c66629f52a7ae6454828bb0819a53fe02f6295e48f93b438184d7bf1c0d16fe903dc629784cfd4ef1e0ad366aabafcaa7420613144f0fc524b21b87c5b85c1cc62d8ee3894725852fc0249cf4223cebf93ee95cd18a1126a12bb5b6e38b2b830c3ae1da53db494c2f79214db2ea01d9ab673894b454f3d068b4ea64da5d691fc5c3269572056227765fa0a3d21a82e06ce9ce5572d51d3e785d4e8452fe4212a1e278b3dc851b9fff897568d384aeb3bc53e26553161141725232cf378f14db86aced648e88713f734b404d161b91c1d697f2f91ade3220da78912791b4e6db7e04f3c49b2c12499b0d1de265739ac1f30f8ec08e2de44fac606231a01c11765355f261f817a138b158b10021af9a5698f926608eba166f4ae7aa2d9da7281bc936f802b0747ce63585f85e08cfa9a82c0a3b361c72fd50aa92e2c35726c784a2496477e8b1fd7d6b7652907571ce7db5edb41908b4092b199db77bf18caab17729ed550b8ca946d97ccf8d0565b2b80f11697d3c13bc4dd32965a4773bb6328d39f8cc65c7beedffdb962374c8b21fcbbac7ad2e932699dfedbf7da825563c3149c41122effc861d75bb6e22848b09809a920ad5c4ae1b7b8e73ecf09335f8672a60868d12387f20323b5c59de4219e076ef0d64e61129d501fec297b0b17b75841015ff768e753f26a8fba3dea9ba4f2e7bfcedcf87304e09673c2ca68f01ac0bc30d2bb8a3078d9be0555aff09c929501a4bf5f010a9b717d259a0a652862ec905c770c9798431e9a1f497910e81ad0612a56e89d488be464319996d118784f95ff48778d655e077cdc1a6cb800f8295d1c9f1f762f475c50832af8b2c4175cb0f3743891ff9f9c675dc42d4751bace01ad307f1b89c7de0c78bda17c534bddac55e19f257ea11dc00e5ae6430fac0703dcaa1b33a4d4c85ad46ab259c02d61eacdca3e9630b5f31050e51d423975ac27117bec976fbc8a220c0f4d7b5f07152539cf8c0f3abf743ea3f2525557f1559dbc792b93695ff18ea3a462dba5ae64a5ca519eae3cfc1577542b7c4de2317254e0a9092770b1cb200068c3222766cf67327270cd8265638ea5c8db055677413c9260f67c2a801576d6d48abe5807fa3e0c7084c5e98d6714462e44295e95b6399932c04dc5ad4fb8a6ddf289fc07342101964e263531eafef28dcf53f3956f303579c04adbcbcccee69ae15883948250c92d79e549b23b5c88d446e268468bffbb72f134af0e60a674effb32e2b904db600beced59996f3d8185a5af4d6e6403c134f33f3b352d66a886b97586aef7e624919f830daa1177980ffe8092c4724b4dfe7e7b493cb9f4a38118fe704f34bc00e6b41c68204b7818e8d363af5cca374ff091278f79833be6654017df17537c75b82ccd70162fc3e03b857ffc94163ff733ee5b9873949e118b978a4266db952dea54fb541252cd18168a471b6be343e26d9c28ca79a6caea2e5fd23c5d506eef4b0e25fbc0248be447e70072d101fcbd890ca305fe6dc92fb94a33ea93e1e176d9ed326ed242f8fc39b3ec072292de9f5f54275ba074b5642e03f59e62a8e9152abe3b2fcc8a8754710ea86379aa53411d681da620a28d607655f65b7eba4cc00845681f7fe61d46acf1beec02a1169bc4f0dcf4edaa38bbf557ea1f9c2ec89ae65dd1e2dce02f5533009d137e81905682dc704b0eb4bcbdd7ea1938e0cbc7948a7c439b2f44dfe105280f78727171673d54b7cb88e03da89d5a09819e54fcca4aabf0f711cef9e2a747d32a976e8dc3c7879544cb5145bf02636cec04f20e72e8a4e82a2c9fa6ab2911af6e015c16b128da5424ba48e9034aef922856764f816d63f3363aeb3f9f38ce635c9d0eb3b8914b51e825707abeded09c2b49d1027e16eadbc501d70edf22376cab675e5cd9bd2fa8914e376c9ee983ead124f0eed5eee76896c692a9293e12708048614ae5b1fbcef1835756e64bb158b5fb3ccebd26c88993b02e7530682bc542ca23429094941f9699d8f65a7010851a5a4ab72fbd7657c9c653df51b6da411308a96d880074064ec3b25bb8d70626d3dfec71c632dd5df92f9fde274e2666d3dced9b1acacc7c4a1bf11ea04ce8da3eea198ee5532142f693488fbc2088840dcfba7f2e9e65767914c6869bd2cf9bf96751272a2452b6904eada19b3dcd14a6dcca2810c01d4995b78a85d933a5d3a4d5787baaca62b0e5167a0e5d3c85ff72b261541d12816298d7f11a70470ba9ce97279d969616744feda0e059cc5fe05c520dfcc5c603a4b4485f1646473d5a82aeddca237cf9945c42948ddf14b1d0db6b651ad5291fafe09652623b79824e6b7d95baa5abe7aa6fb4fb5ce7cfa60d6ceb4299559816bafb3232b3dc2d07d1bdbaac64e4473a7e2e0ac275ce171e90297f3ffde42749a082cd76c19a5fad9fbf9258bc1f59c362e912438b67b22175859d1f2e86304c42d285fc702420fa9d596583aa2d849d41f002c2f6ad9809ee99cdf507890215bdf6c38dec2ed3400a7b3738090530619640ba565f267fdfbdf637b1ef3f9dbb2282b60648d9eec0d7a542c1e3122bfd1da4d3d12196ee040dd7aef75149d4b8bdd79f6f6a41fe3d02b47bcb34553e575ea12267d2061eb4267eb75394373b626ac6d0f7db5d6fc6c53dcf1bd4d1be915fbe2416b11ed5d92f03837d815b638a1a7189079fdbcfcb6d2816b48454e0b4409c6c37138ca97fdbd5e112f4e44ca82e75b80a88c52fdd127f454e9e0ebbc76fd8941f19082769fd978a4c3ac6a1c4654d3a086cb4f8f359305061b372cf02eb253ff558e761857df300af601a21529b4cb2c29975f715f51c2ec4c371fac354f9947d18490396dd0fdcfd2765648fe85de8e8cd12ef97412b6dcf42ea671e279ad3ba641d7e51aaf519761a3c094def5babfb9f2433ad727483221a586db926304878af67c8d8614f143ce02d5fe98300093dd13ccca68ae1c872afa39589da09d1b2a9aa7ea0a0f2fddb5a6f8ea1ef80fb11ea146413fe64f9a3e5d36060a6143c0648cd63fa74a943e7459a68a8ab5726d57be4225313bc500c82059c3668740cf00eef199e07245113d165e9ed24b04c31d6e5d48970a0add09ed743fda5448b20fdb438f65f9eaf9f293a16a9f462142f0a7dc64a9c00ea71b203565b61df90ca27fb248422f75dd69b2fed14a92eaefbd44ff6f1b9c38ec3dc6295f4455e2ec5d0544575ddccf5eefe06c187c80a1ca7799e6d75012c1e3133a7bc6e91a3877c90ad821718549e6e0dd264afb8bb24aa338391b2ace79d843973c0c741ac487a31c376bcd6567eca72d1fda47be3cbbc144500091aeac0068ba06f6a0465d6177e74e3e14390afb690c50385dbaafeb4ed6e502ce72a2053811fb78b06322ab66643c9c3828442c535100c499b52d465b1802b3a17eed7d5609868b37ae2429f03c3169c75e69e11e26ddbd52d65a57c2c9d605bc1ff5bb0f4fccc47a6536edbb9f463ec0f675ba2ffbf8427e7f8c484f2af433776d039106bb434546df4558b61e25e037ca3012ed905de3e1ee42080f6531460fecfc86a91db691d1f782523b797ebe941458a5a9b4dc62527232dfdcf8923c6c9d6785c27b17c3fe3982fee4c1bf14482655df0511ad54fbe7d8c085a178fa0f5eaac0c4b0e4bf1044cba94b6b547f3145538f4d18220fbd477ae95f032e754756e817757f69496c2a1b3f093cc5f3fa5457bbf512b52ae0df99f4b461eff8e76ea681ecf1b2c235e8b9f9f2998f0603f6ede6242890f659c2836d244d4badac7ca59066eadd63a9a8f25d253fd8e3506b402574a5df1bcefb4bb66ed62a7de54191ca35da082b39c2c397e2c63beae3dc43ab15fd661c806557c8ac49d64a424d6bfb83c686e11f55d85364f1c49437e55dd0b9afa288287c599543d6aae9056ade0804d673610c6e3d50ffd9aca97ede90eda13222333ec2a070eddb36ff9cbe9435882436907da68a0b8d0e679533a6212d7f536121fd4884755d3ae56708a4f1b7fdedaec2b8ce69eb51a9aaa9995a1ce99b3540c22fa3a4f1747a020f859be9e108f0c4db5376fcc2b09552c9e90334130322976d8fc765eb7b7e233ad203a1e518e6511089ba7fb953a7a9e925300502e23a4d0984490a7b4d47008e97d1e8c54e1edd2d6c3f0b726af54ca5dfce09e6d66ee7442cdcff39e48357be54e6b53c6937cb304c45fb576e209ec95c308c8408b2aa556435d54a2b90500c2859118a8d33685dec37e6c90c3016e7792f52ef2a8fc95e5e790fb114ff6095f4c43bdb8336fe70724a1b7436c67066a377aca3e4fb736dec0262dc58c059b4ab212a39b371d39d083e9dc6e14c231bcf56fa8e978601f337e388133cf89678a09cedc27a7fc745c39ccdd67949a162215724b34ec598a1739fb7a67161e8488a7fdfe9350d41552cf46000aa255d0d17a49ff5ef193a1c1c46cd157c3afaad3102fce07fb5e66a1305279ad232bed073725a63a6a354e51470bfb597d8ec5bd4b489817c7511bc6ca7fec029f3f771e6440f1b01c1d6564eec7c524463481a05ebc5514b0d83ae83378ba09ee8ec0d661a2afedf1be97bfda0ff80bbb437a750c28601ec541174115706f243bfa3a0afb504098b7b5028899fe3805c92d2280937d71d251b316004d296fd899835c4e93aee3a4f77253332f73312ada478e6d5a75cd67b5bfbf16bfcf76d12f264b12b9b02b39f748967cc1ea0ba111cbb6be410303426b5d51a8f3c5f26765c2fb969b1b1903426b3992bbf368e4057698bebab16734014dc26f4b5341c404e6cc4b492a01717df74e5121436adf7e10449a5e82921cd51d4070782e7dde13b27c819bee0f7a3ca82cfefe0c978ec011d708081b83768e48647b88c35628fcae8981c2eaf641cb4385603a8f617b441645e04fa173a3777f8a21f098625d2e9ca59a2e5b8874a6dfedb0306c98e815169378a543c339cf5db61738e6f474f3ede35d2d097c192af35d3aaebc4d6d9b08d424cdbdb02feb64723d458dc600ac5a6b816ed2ef79a256f2fe1d6a9fe563b2aa557e3f7d4466d8fd2ce0f53c516718e8f0d4f9bdeff3b1c47d99d64a429b838b42cdd9b30b313cda4da88329a499ddc3168161603ae7b3872c034184170d9efeffd31a2185e6157d7dcd4da1d3b1720a7545afe63b8d1773992eba035a15166752bb0377f9e0595010b5916c93887d0e61e35fbed5f758fb4f74ddc26a26fb6b4f5a9df3777235267116ba95e4a66aa6d39b725aacc097b844ea5419739a2680afe4f4974b09ecceec645d29b03f73f6e3d98de44142ce7cbe43634a2bb90818c1bc5c3809ff096a5e7c7b8490f7b6a87af4beb8f97fba778e8c48f31b33775e7ec6610227a3e696029b86a269366a6b0701ba15daf3e2638dd3c7ee4c216f7a98a21ea5a99034b2145b8e6b50a80b866ace9b44fc51aea4054495ae6eaf5c504c9f376858b2eb5934f7b9488a38c6cb0195dc3ae2ce7cedc147a64d40bca545d3605315f3597e6c4b2ca69d9530f35b8d91415b522a3c6f8383609fcdc76e6d0b9b98bf7389202411e04a94b57f846bf60d3a5b0bd099def139b4a31c1760be4d06d0a3cf51bbf77491ceb4bc43d55b8581d709952450b3fa3d7600a9278e0d6003526ba9d01d1edf955729fe2d6c10f11976cc29ecf57fb23a9154a03c2738bd2e80ada98d63e2dd49fe0f8a24eaf3ffcc45984e8014a9fdf78066a21c6960cbeff12b7c725003906c5da7280d71b14191d2d7eef22039847f66093deb7cad896c9040690c0c66ef37849f094ef674af2ff9b7e9ecf63f72391d8a76feae60588d71ce0b3140f72950f5721b2b7b1d69926811f03b670d3970fdb0ee34138629d7bb73b65f738ebc01e747f92f1d866c8be606f06d7be3ec91661ada6cf513e645ff968eaf45f518996b2c1a7801059038cd3e49b80df529473a1eebe5d6f2f739cfb712d8ae3f870104dfa66bfa52e0b03697c90b652c99dd7727faa751c9f42597397762a803440e80a2fa230ced935fa16751d04fe406ccb2345d781b618af7848d95546c6a40a4de0a3790d42392821c31446f61253e22be75fc2343dff8c0146a90f91be3efcb7dd2e2f6fc1b56ca7cb7c06dd78ebc87572c2af1500d2eb679b0fc7d04594427ca80d6dfd993f220623b4bab1fbe22529d1deccde942c4267d830e583fdc779a6c1dff3aacf07f0b325124c1f4d5c3a3ccd219055bfa9787325e075bc714377d1edd5ad0df3d195f19887a1d767610d06516ed52bebcf3f96938a9a6f49db9fa5e76ace189ad7350e0915e450422a065d9e1eb9330e86376a838c5e91fd48d0381d46156586506ab39f08d16556a25f6d2edd9062b1d30d402ae6cc1493bde804436f73699b915de99acb9a926f85d642c3512494052ef1f163f9281fbb259896f17ae3fb8c346ef4c06b941a8cbf684dc57ec724cbd290b7283b807a3ae65607f854486ee65ce0acafde5ed3be41ee02d976441a3446ff1ebc3026f18cfb0c648fb3e17bc0f366116e604a9bd5797ed14cce8fd0afb27c1a93f199cb4f2b1e903383db1fea12854a32f641f6b35e377cf073a8536e30dc88d079ca753afe87841d15ea8b45e057ea969c1c89db5c95d8ec2ff9e9d105da97afc9a2337e92b1ffc1a7fbeefc8d42df6a77b0870cb4834064c01e33cc360301009523548c12823ad228c093ce23d1591c4ba84832d247c8385f2c9d163f9f314e62bb30e558a19b0cdb347abff307ff5f010d6e7d4f52cbcea3f0d39128aeedb9717c5d7744d062f49cd193c4ef2d1f990b2abfa5729f8930e58ead0d11376fec9f999eb6d168ca0ca7e0874ad01cacabf5f10e4d72dc8c4f244a29e4780d4f7378965ffa5cee022655db1617394dc0f8e6ecd06b255bd5b16004046d2a977b49203bb1e67905751e7013a05b751afebea14c24858b64ec337b442e1a96fd9a070c98bc52bde45c1d4d8c8f5db49e25d6dd59667765da467722d60d7806515cf0b994a14b5fccc672fec43b6fcf60a80313c7094f7bb877cc9b1afd0b21d36c2c2781110c90965efacacbbce0c973ccce87cb6da96c87522be66095e71d66e8c4221bce41b97ecf7c4b4575afa4a220b02141d8453b1d7ab716203ace35ebb0e78ceaa0efd85ce49d8c02a9f226acbab70d179d54749428c34615280fba3862ea669f79edcce216672e7876b105055eb8d82ced182b4ce4e0666e43366247e9ae806b13672a12ca20e6e0265993eb2d8bcad011fff662e5e436e762e5c6af8e736b2fe77d252bda06bff5a5289a6096507917d47615f7bd9010b2d09201bd1db349c2629dad1138ed842f59533196e437ba006c5405a3939fb67eef9e8b7756d939b9d0378b51b48bfcba7bd9a5a68a503f6d45b06d615c628ac65f78015eda01019662fc770ec5dbbc407e3cdcf74874c0c64340c1da274ce51b40fa57942f9dff7520231d193cb873b4725fbe1398cff7260eb277c6283bdc6bfbeb20c01259893d53114e197916fb41623b4c4787da200c62bf9c1a342c16eba74efab8eec2c9977f655de737b3dd4604dae5fbf71a7a4eec1e869ab2f2cfe9308a9435078ee37b8cea34601e94e958da6824f9a73bbc01847e0df412df47b7aa71cd1178c478d23cc42f1e829cddb646707f602e45c6f17b5e65bf92e4273e8c9f872282721f295eb4345052f65572074960755c679c200fec263fc0c32fc3a9768a0e1242fa6f6602b9dbe76ce600685716308a14a96474bf0ae89c9832fb2bc54e532801a9c8abb7455663529e64d2a297ed53f40c6e2c52c11b36cddc481015ecba1d5e0ed3c36620f3a2b5af849e1de2778a5e871774aeda68f089b0c92a6a9389b95a682d85c4f1ffaff232bd715599f0aad6c2e98906d635da67ef3e2be6a33a1867a366342caff1cb90d707521197ef39663ba430a9ee53094e61265459788d587b30ab1ceb44c0544b1586e263693204f752ffc035a6dc6f25de3a9cfb61e4d81506157903356cb38ce16631436bec2c55564e6f9a650260775d7f6bec0227e4f56d830c1060eb9f59143626ed81c23d2c91a8bc5ba67c49e6eb7491e125df8785b9c35b45eda6a41ac032863a7f7e57e6243070e126e1db509914fbb31659554d0589164c55d6174efcf42a0af649121a451d2e0a18e6066f03bd9179da6c1232c6ff73556f81c410a0e5c6ec7aca88514471b927da64a9a75104360a7b6f6b770f6a25b62843bcfdd2fb9d69a52a48e11eaddafcb9596181d4d7d7045be0d92236318c4de16e34a8d219a9b3b7ced06a049c18611d41a601dbdfcd893bf6c2150a6bd4239b1f58a5bf3824937803e961375a232dd72c43a6be574056676a68d34797628ad9de0475c301f0652724d8fa15aab4d207d7a2ca977b6c61d618873477c27587aa44954a51cf3707360e81fd92aa82b352940d18cd308f1b066c93aefda5abde31890d3c8117851f1a2727ddd115e3b4b89f07015317c37523a9b807faba97cfd58c1e37dff8b037e27d57bbab0c98304e01553c94b266ee05c95699926ea3862fd570debd283301f66c7e39a3f0dcc9616c76f9b212cf5109bc0b9232308bac2adcfee25c04789db5f20be021ab72b393186133f479c31353963dd0586e27b9c9183a528490dac6fb9f03ea8a34711e578eb29c7b6875823217b8233a218e7367f62f459e6d5cb06fc6a26fea940e47932347f38e4ad24641945060153665072db3569d28545ba8d4e8fdae2da99a378e270c6175970c2221ad3eb4f49b708be7c32cee4660e2be9d1b3b6e3bb48f732259f12c8191d5e1fed309c08eab6a46ec9d95ee10d64b26cc9aa02e9305e04e00f6ff7bfa5746975b85a233a9eed64e283e5dd9c9f11993eae99e9dc395f7361cc3c18da7ef85353d9db213be9962e3b0d6acd58f4f41808b2235908a4799052dac26f54317a03ed1651fc14560b6d0343ec8408c132a705d74980e5226dc8b1071ed19c38c4e80e3431d9dcb669b800a5bd5046f703c3701050632f37525d2e1fe2ad40705cb7bf05313b8f81efb8142c0c0c2338b0ac03ae6e90e23e4ac72a00f9920c98bc53c18f730707db2b20a20b9e92d565ff373535a31265c2c37667bf764b34f4a01ec2b54dbf88c7772654ac45dbb961f8c4d31de75d3112add5ca1d8f5f43253c344ae1737eddd57ce4be5df2668767e47120efffbf8ec8319671d305303f58257e4eddd31a2d56b5ee9720bdcd6712cd54c0a0f25abad2f7607df9e5a26ec4092e3b92e38d6693891c65085470fcacc255ddc0e169396817d1d7388302292ee89845210413afa4edc3268d9957704227225ef814a1ec94c27bfc7dc41596732a14e61994b3a436d674a1f757665e2c7cd3d15c38d96de7977e97b7132ac224b98829327b4e8a5683bc0aa9a41831b3d423694e37777328946f0350f3aa98437fe9c918aa8ca19f2f71906fe07652025e577fc5e74ed77718ee485842503e8c99dd8b3c4ed92325b52a3b1b15c4e9ccb5c5f197a1d43fdf749721ea3654c3cd16e256bf88a2a236fb2696dad02aa56322002ac450332bfb985c191bc6504a7089485bc3db52964507a71234abf82deab63743d3f4cd87e24f77bff057f04b56d500533729bd53085f47e109f7524a1537d1b3603a01cc2e6e0409b9a7ad04249180445b5b5a6dd3a190eb15bc2f03aec850a7847aa5896d95efbf07deacde6604c71f6b280c630948226731c4c9cd96c97793342c84707deab172d41e2f5d06cc852b00fcd642519ca21306b94365044221d348d600e1514a3655c60af7aeb7bbbd85e9545ecd2d3111b17c136145ffcd069e450b86fe410675a8cafe3d92df4a92084edcfd08ef5ef5356868e6dccbb0ab66eb5c2e7f7be628e83deb87080232d982c5c9d4f5eef3853c61fb476c54a9a1346c3f03d5dc2b50b40c9bf03f1e26682eb101a90ce5aa9b5b303011a520fcba7272edf8bd571ae3616254e57d80540d81f9d9b169e606ec14beab33fa0cf5c9cd8abac8c2dbac7ca34523088be35135a9635e9dc605a2027b72cd208c736a2711c966c4b15e7ffa5d3c14aacf322f84db2ed4fb3523593ce21bb8d231da3ef61a896cc0c5914da0653f129d7c210cfb7c29703c51208b96f51ff22fdf1ef59146eaf853f045e38f58ce35f209e695e1910c2f311b9672bb71887ffcd141966111b6a4fee6a8e71a42897793f217c70c3f1fd09875c2d24ea142a7b6fb70d69226ec9d95ed340a1e7202c138fda3228f26838b544f3e3f4c7097719d9700935279f00f661f5662cf6c3c9c949e81dd6b67594289010c6e94b5534698a4ed25ff2c02a063172f600033810f1d90f457bbee4bcd8391f24edf30809aa884db967f744d9a4f49ef0bee18b09cb7b617a4e5a0d26da0553512bfb6ceb2b609569a7d1a94e411fef55ceee46c825875f771272c10ca06a947bf08e395217e95c839aaff5ab2c9662f265b1fc57368c922e3ceb406e03e14bd6c8d1228ca31399904109475e6711ae7ec2cfc7640c983090932032c1b4b8f1e8c17274a548e7f63e3ee599218e034b11b27d907d4d2aa0d9b61e81a667bb42140bf3f53742dcfd42c3f25e1f857ad2150a1f3406aa6623ce70b8fb1454755a9d9f6a401428bfb1e5b158d219bdff8bb1a645a3c3c15e05c7e6ae79e5085763b53775056cfc6491b48adbb319b41d9554a06479cb5847643ba5e78a890e512600767e60d21df2ac4211d2c84984970a98ce7f45b129e56a02e1422374de7a6a13f6fd2aff45701203d1447e05919258f34eac4aa0f81998cc9cbdd6606de0d85568deb5a50cc9e437cc0f8e697f4773ccaba8903f13749f89f13c4a101a08fc308024f7cd96eada34e688f386ca1d6ccafb7ebf57841c6f82fecd5846c53ebb11ac30815ddbd03c4bb9a75fcee5ab41b0e944ba80809ec8e722be8468272a0406639a3e1e8d282ee65a68d47bef8fb3397ad3bb5a83b396359f6182b15ec69cb0ba7625d552246c45e02eff65a596c9453dbf98d0e44a20f4bb215311962fb6cc6db509a0c876e307570f2bfe9a07f82cb7f9910d9dcb55643db553e60aeb9367c9914a550a672e7e677b479e7f71ca0e75e15d35700db03bab511648c64510704b29a70271ed76c0fb18b6c5c9dea04792a60dc0e1cdd7be00859405cf74a9216b5ad78ba4412c7aa81b02b3e990ecb3ac16aefa09405fc9e0b68294f898ec65946d920a89c634991f4b833cbfad2ac16a5f7d603870dcc5c95f449003d85fbd2aa8788277f2aecde395f8c540d14d2bf280e75916718322e36eb3ad267dd9a4c067fd2fb840dad4a413db9cf6ce2197c74e1519e262513543dc5e17145a6ded439681a4535185a0f74fff1aca3a4e0a99e224d284060da321394c6c30f03f0eccd4958131a68da76147fca849a24b8e8ec0be8e9bbae4c00d89c4532b9389f0e4ecc3690347151c4644cbbd7906904a50e8aa49104bcdc6ca97e71d41cce4f45b1a3fdbd6873fa8ec0d59bcd7ba35c19c21c84083e19c24ecbdf45eaff9453168b4eddf9115156c8770e869435a6bbacacea8417c2553311786800e301600ef0f889e3d78aa1cff6571a1ec5289da78ac772c02f1589f1d157b20bf49632c63e779bfd972a95c1abfa20e74590b3043935c540796e27ada55ed5bbdee78b3a4093e5d39329ae19f44802660ef433212c4d1f1e08ee7b7a0950a7e29009b486c0e0dae6afef8404d2ea978361702b5ef08cc2a73b33304f27aa08e73c64b8beb7086c27cf9cb5ffac9841a33f2ebc11c5581a4e34fc396f770502d511579e60810cfbc2fb117e48fa871c4ab58b3c9f3cd0c8e00a0a36238c6024260823be474f7641cfcb64aaa01b77befd5857d53c7688c2afd7e6d1fba66b020aaebddd369ca81e5f6a320b3507fce0b58a7f0c48ee55222706703e286c959d4f813855358d0b86bf8258b6a406cb4daba1361547f25ce968db382a9f2327e4e2dc520e97b0662bd8d527d24cf1da3622a65bda76e4e2e2f01b315dd4a0caa88fce670349d8b0518143e032f11ed381eb1546f9dc90de422b0c9d563a0857e9e6c0d8a413424ed5fb0b476cf57cc89cd991320b2c55a3f453d9947997661373d3dc57f88297c07794b3d4a439d5d100675fa53de7e511d56c9be58fc74b1f24227de25edc86e0bc98bccf6288df18f493177b0a4d03a879372acdbb4e055890de8f46cfab2d232464ab20b990cabee947cb24fc7a57b0bd4295684f23d1de43243fe5cc9bab5b669b603bb60af2c06751e54980c99abbb093e8ce61bf44cbf84bbddcd49c44fe3b465a44cb908df041b3a9dfa033151922e04b3bf803bafff4bbd1dbe50ed29e8d5dbdbe56d2e3ee631feb12ac9e7e55e464b2978c7e0c50b76021e46c206778ec94e6a53f44ec06585a8463840d72f91f097b27b2d5eb41a9f2de8fcf1cc3b71174447094dbd360a26f9f29c36d80f19dbe3c527336da6d4e5934556abda4f40096220f27705c7f9e191b2699b23acbf1717dbc3541f97aa8fc0666ef7f588444f0dbe990f27e0f48026d52e328376fa246c63987a626a26c65a02a5930eb594f21d5c23e092fcb151a9a4e1848d03df2de7616960ea181e42e3a9e9ab640fedbf1973c40a7bae40b396d6670f11ad198799fcd1cee43e347d99f07c93763ae2f9f2dfc005b54ad09a93c147e4ef094b95da75ddf769f9417cc5d11671e59132f4bd02d9e6b725e67dc9cd6bc1451130561619808c6aa49fa4d86cbba60a2612a56c2b5b0a37278ec5402d5a7bf986bef1718f6d38ce89f98a2d54688f50cd89321dc6d2dd408a0e3c70215b8e82bdfcd410bf522f474f8fd7bc6f9ede1dcc2bfc0c3f791007ff069048aa0aa1b2c28c7281b608ece77dd5987382115711fcfcaa51d4dc263006b6ab2982ef9060ef3c764e5f3e9b1fd4e2fbcdaa93f2b8857371ee8de6630766ef074835a7ae1dd3e2f65bfd952ee240f4041741fed9905cd0b01cfb40a882da8852151d0acad49ba4ccefea0326a384a5bc17a8ca7973d8898c3e3e2f9aecb0f0315a5b52554973a4499d68faf7e6c3c5e430fe5f13ff17021afe4b9124e1b784790f138382829716d279f44b4cfe39235c154cbd4184a1eb8aee5f9c0e4bf2e165b3636c2600b61aac8f09c8b01827bf1fb5d02f326887d144f8732c2aacc7484945ad7e14fb6da58e575c1efa5da188e74b910a69211e548235237b4158deb873b93e1c3104b878f4cfb91a4b0f321951c24a3e9b187a9ea65e90936d42e0c9228be803ef7e2b500902ca070171a03a279bfeda384ffe9fd3362858ef92ab72e747c7ca02abb934faedd616966f6fdb0b14a0a1e57fec8f75abb8e592bdace0dec624492bde39a980e81f114d38edab201a1233471c60ef95a3bb8806771396d867c070541da51888144b9dbbf4d5144969fcb0942b465f7fce5913ac112a6dd0a9f205ccf1d1a6c4d5cc1fb6d01d9685846857ca7ffbd522d0e9e7b17034a0e618764b58b26e4aa6a7c0d2d369fcc39bfb254fc55c8aef39bef20a36f6b72ca64c08bac332c0b0ad00647b6f4bc5bc8438fe417fba8e06fdbd8b8fb3634202229020e5c9a810ef3f5d84f85b7d454f03cb6ed0bdbe73a4b0b19e7ab79ca1dbc34f2ab0a0c0eafd909c06df953e537f73aed2e5ede45f285219688f58464b421ac80068f8e3cf6d457403d4457b79b0c3d9541c40e55179ac009803cf70d7b84304775d2df9b61886c0ebda6327df5f35ed11c8afdf4b2b600200ec0840e383a4c863b6fc490ff178b19c8f748abe95b5b2be191e75389ba071688b6b9b080738c467f2e50912d2d6f46f5361ab6e1bd32b5c9426b8c0147803cf9e891e9561af5a5f15cc64160b1f55f7aed3add84117a98ba2ce18e9a1668872f4c81dfc69d1d296bddd94a0bf9d8b07830563ec8d2a313e0159699c7f941cf6ee6a30eac642b4f2035d347f73a41971cebb9dbb22682a30869220c9d3e1de8b66d0fdde55f5c8a30fe54d1c5fa37dcf765867321982f64e22d8134a06ca8b4c23fc4ea2daa1aa0346518e2aaafd0e5370a5c1cc3213a3d930c8618f0403484d74ea598a88c551fdb6e4838d5421afc4d38e7b005cbd97fa4be27671d30dde548a7eda275319da2fe2fa59a576785d3311466dff6e1c4a2c13a3ffa459993cee72a2a6d924f70d23950f3162a58d94f9233f9793c176dce621b91944354d8be2e7843727bc05b20f147457a2597b9e3e909d95e016a652afba08991d86982d9ca5f6e27eea04e774e5900370476ca48c90fe7594a81509bfd161c1ee4c76b75f2c628324575f9586c88bcf4d5f0c6b16e79f7aafdf4d712f76d25838edd3de1fe082a7b944ee4f0823dcd3430e7b299bb5ab3f94729a31de86003a5e390435c47b6a1ab0e897b6bdb77f3f3956f7c8b37ac996c30bdbc21685da6d92a0a33f778ef5354217ca09961639c00447bb8f419f571f977951d589030a6026bc9f99104da454cc82bea2444041d1bb71537fd66f67ce67a0f900f951c998c18dc2feb0d128fb8065cf0e9b6d317829102cf09bc019c1d1e5412e38ab3a704c6bf7eb14a61f91ccd7bfce4fe515486ca0468c60d11e644e869fcb486fce2363c0edfd0db7c8910bd832977039b1638b21118d0a415106977470f9eac2a08da0d9b024f0eea8e8bd0a65e47c47e377e43b3df40e0c4fe6f211196fc72016dc4c58ed0703b48779339a3de173304c38ad6847952a841331e09fc2b98f9cb35803b00d126eafc0299b5c31084c7e9c98e22d66f7e45d2d43dab29cd41e237b58774995614bf0494d73ce07421cc53719e1a50f799cc9cf7b0c38ffe3752f994f214ccd11b9d34df8f6fe08969c16ea916671e66e7463b078c6a8491d2c2a1ae2225732ac4f33504d9e29fe9861eea0a3d199bdebb572564ddf3f6d6e34e6d66943837cb29d0d6e295af1c0531ae7d7ec8f489ead427a1b4eb623bc8fea6f819ad503d511908b9eaaf9554e5c9a25901326f6ca9fa5341d00d0888ed31a2ecfad9cd3ff633da8f1753b2b4336b5009403e65135e5e4aa8efe69743339cf560595e672afe798b5908f81d9982c5a356fcd9cfbb0102d6d85f365dbb6a732e294dcc5e536441f685ebb2d99b16e108a16fff9ab9d766d0cae32db8b1812f0cf2c7e173be7818b020d04168ed8944ed869aa307dca161a8ad23693ad21c26cf451cd390ccc1fc27ebd5cbe8ede3c1c2db06e637a10d6e7a735a6af4c0328dbeb5c547874091f75f951c36d7c49b68e26694536882f1384cef3ef304f71db2132e904f3874df89785cf69b51898f34258e6befaf3e572007047696e7ab8c6e78225906eaead57808ba7117493d2fdc2858ecd1473a8aaf423becf35e15c87c76f01a14ea9e61bf8bca696c09ebd39c4eb3b2023ecd067eeb8fbc50a38b4658d54b0b2ee32bce3a2be03aec902c22275c5a7678b68d5579f9efaab767f936f467e0b563092e1f4efab3446b46120dc39299c8b7af1cbf044cad5c82e8cc3da1727e45d04ac4d2c33b9d6bf0e6d40ce29c779c6632dbb9f0961bf38390e16e4c0bf97fd1b462e06d458b4ba878c22554b7a59276ee26a4c8b676c918f280e623c20262e6506b8ec00e39469b0e002d36f347e8971924a286e04953ac6a5e5af939e861d6e87d259e67af9af55af0714f159d58c0758a5c8d494522632c42a247de824a14cdd5d9b6a9bebf5d16fabf1aba6359773e593ba9460a62bb0a1ab4ac3981ef09fcd50701f534a13629b891c7e9ec220d04b173a55134134edae9b4de40a156b7b4b2f34906f2111482473e44bedd4286a8a4fdf4304128d14c3311d6ba65e47de482c0859250e16fe5c6267c126cd38813a3da9de2398b3f8f9871dfa3527b6197c2fc74fc7540ef5c9cc98fcf40de3d488489811f7a3d8619489c64d43597ba2c9f00831bba1e2e3fc07cf2d831149e66d7e8be0a038ddd53d18558a74130910118b8802b1de2801bdf4adb38d255866c4b15b8423b979154023abd477a4e167bc4de4b7c3a286c9896eb594bbba089b27f1491cb807d1d61d56f034e0c867c1b272ae5a189e1d434b85daf7c411a937fee377e01d59b2ccd10912b84fd66a0558244cdd7ea14a2a51148b980a8edfc3f6842eccc37a8ac8fa50193b557bb50cbc572eec20c86fc6809e1f0fbc508a298d0ce4b368dada7376be01a00f90b11857d84525fed90916d256baa5afdc2d325ccf44fbc9973fd7ec9405206baa92b8f92df608a4ce148a49713a43b580ba97b2fe33cfe9ab8226861d97c42c4b25c40d4e9f0e2c1274da0ec83bee2f0364aaf0be2f38acfcc197507128b06a3c8d86bc9d270ec08fff80f7482422959fcda8463a864362be7f3ed6babc4269e58a96f21a522e7a26e7e0cc9ce0181e805cea5f4041f16613009c9f5c857271cb366714ca9a1f6e8e00e3614f758b708f6156e6e74d23ed461e92ccf233d683aa08d9f333f54519435015f49bea3c872f8b440610852fc37895315e6c0a1125765d297fdf1f9f1bd1296cbfab8c7d2662384458a279e307cd0e0170f64b40ce2eb76559f8b383c7367c5de30c5d0eadda3de455ad600d713384dd4ed2772c03f77bbee77204e1d2c435983bdabdbb5c3326a630636318bcb91118f4c568572d5065eeeb6fc667908f972f34cac04cd81a7bea5e4c26ad8752b17bf2e5dcae6199e15933177e3d48e4288cad38c2a98435fc2f1939d89903a1147d936fd03ec56f6b026cd62f404192d07cd9db4755ca16f5f07fe58150ef2ccf42916671296b44425b050d86408e0d183caeec6302223f17dfecf48fe6250b7005928de11ab886ed0139a7ebe24d711a30d4d06f4bb2794d9badfeb370662aac7e01e1bed34bced6ca8e1a18ce9cca4cc96c97c3f3f34fd7189b2fb100e4f811029d4dda8e1e9447465e7fa5360730d25d25da76d7b91b22af4bb793d4e752e3e22768cd551fed487c0086dd79d1d8ea184bfeaca70c6a3b8fabc6070881e9d994f1890d34ad8b2118e11a4dcb26c106dee5a0b0adceb3a86313ec12c6a794276ede355e3f4a2609ed2dfbb476e6f33cb2f0d2b467da4bbafb161ba02d7dee416714771703742dcb1a8613eb71a0321cec362d04d193c5d3d0acf376f4897562ed10c3c72150d7c67abc56c00dd41aa434dde0cd8f4361ce32aaadf436c1bb9ebf70d877a46df93b7272f290d5e49f2f62e470979887d37933b03d6e1e8970136a024576159b2e676b3bf89d0b61ca8fe1535144b50ab1f743c5ad2cfda6119b03b20028428df23825b337750132aa8f434950ef8f981f6141b3abda744e2c7b85317b2e722a07151fdcc0a3ad1d45421f6e4305f9e86dcbbbbeb7b4509b2a6519192b312a45e4b25378eec6bbafe2acbc9306012cc35029c4fe835a1cc3ada781e86710b886f87f0716d7448c88c51c72338cf1390eca06ef358f873f18d892ff863fd763fa0ac1fe69e48b010c22db9027e1acee23973725bb83f7d56ad6b8402dff53bdf22616656a5edeb1a9daa5fe23af93081280fdffbe3df056cc25799f0fc1be88b439f52fc6189b1a98332703a9ab06d6aa770f191fb9a48196916aa6d9d7739e54d7a8f1a12048ca764c7f70da278bb305a22f87be5bfd51e6998e4b1b303e59be2f83df021e7f7d12ee3c7779f9bea677274274c8553eb8f579014bb8877724b1a63c191a336fab92e8db7b7da31e76e8ff18f28c3b2238befc6a5a74b9adba601d45b97717c952b02167d63892e71201f90ac4c206a230f38402c29153d5bf08261db285c7210555f4944186cb75c1d0c174d27e4a3bf717d08e1b3cf72d245d035f967ef857c0eb334f81510240f3cc165a2fca9263070f194be819f343e578f0ed3525acd052e65e6e4135f2a73a83859b4f38a3f7298554d8e76c9634f7fa2503062c1c605176d17401ff464b420a03bb048454057bd7cc330a6e9e41e2b49a3e056c7e57d2b8fc0f78a766a1f690bdbf1dd64b3fa4d1990674d19e9cbe1f3bd5e6d0ef435e0f5889fd38d1139c463e56a29d63fd06cb004a32b5f38385e494f4d9d66aa3810400ce33b8b63721486a46b58e06ba759f38acb181f0ce2a05c443d659613e6fb3d106ec853d5075276b856886e20ca2ba66446821577fb79e9cbf7a830d6bd0795b0ae3890dad80db027c566ebe63715b5400d466bac379ae55029cc45c3785e709c5c7ca1a5cb4da54d7cbcbe8168106e6fa740033ba0d018fa9156f73b0528299b8975b80d0bc203dfb6f2af514e4508f8b87196e45f02e424b274f0a48d0675ba058be94d8e0fd7ec474249a7268c1782a902631d0ecc2cc1019abe084a65b031215d61b4a0c8761bdc3173da1bbf621790436b28f6f5392da6d22922b9bbc7ceeb01a11de5fbbb578add0bc4dbd7ae6c3b253542f1453a9a9566d00190f78d30ca8a4334b1ac4841a31837e155f8346a4cbcb6fb8fc3794aefc28903af8981c1bdd78ee3c83b54990691fa707a5a4e7958e5b430d134542659c3340bb593a6e30b66ef56e6c3f4550936bfc1dca96848fb2411bc9df99e6bd3d8a514fa88fc586c1a384444f39108ce3d7ddbc2a8fe4ae614ad6380b526ce39dc4839edb07be3ca7d01babc8fc2dd768aa35b9ffe29408c929b1744de8103df6545de34355e8e2eed4edbf78140a9eca93cfdc6b4629ca75a09e4d057f729520e3b68bc081691a7d38270ac844962be7fdc3136e4ffffb3ffd1600ea9816ce8aa65a4d178e38fa12b4a39ac215f71c3fcdf0dd4a8c9e7aee47ee54b8f4d70e96731b849e3ef5c2da70f07eff5eceb015d2e3e6087602c8aac6114b7bfc916391727d80d72a13dddd84a270e74ecdbfe491a6e844b2309bde2aed3a202ede004fd5842fa5ecdee5558ea5f9a511300f6beba8f6cbdba537a9fed8e304cf4cdb252a21f1e27a90f805ad65db8f47efbfec04f0d1a5a5774721d024ec84e8be5141c503b4c682cb496e87ec64bbf5267184ee4b3866a793b9fdf861cf34b6809dd5697c78af201d9c3693f00b5947483a7170213282d55435327091eaba807e482f8f33d7aa97b046d0c4a3a993ccea1d2e88b4dc9bdfe494274afe4a5f7b87532d2c76bbbeba6fd9ab189f2f65de0796a4e8f6d8a634cee6a3a70d0bdf39dfde36cf19b2a0ffcfa63fb19af3f2f1b5591c8f53ba625c4621bcb783908547f0f8d487d181839b58e4e32dca6905badb644fc4c3bd5c1dcc7a700d531b6106d1be54e1bbd4098790c093909748c8433b109912ac85fc39b276b47ec6c749216c8bf9b4da50457dbd6909b96b58a540fec006c174f1d0d257d3ac574bf25237152cdfeec728fcdf9f5b2ce2d420ada2a12d914e2ae72533aa5f65489d776dfe29d57d4e5d8c50d29ec0540314a8f05bdd174994d9d9825a455b46fe3c53f3b7e794d253840ddb3f0ae60bb702ae313554a97192d733ce4c3342162f7860037eb9d2dc9dd26ce05a09cd5c7fe342e3dda3208a614a7a3b33b4a5082221fc94c1f31349b80afe5facc6cf4aad6416a12aa3e3aeddd70cf9c7cd7ef11290b5673bb337d318c385b9c0d577c5822dcb5538c20dec464371c23903ef8951830b5e8b02b5a4b11c9e77b8ef504e15b174c1c69620184dfd96574f82b05d6b133af0e147546d4307c5a5f970b16857976e777f5a44b285a25344afd83ec2f5dd477c7b206fd43be30160a83461d209096f308d7935dfa655c3a40ff780de99b2498312c7d8a8f125a2cadbd468d130995da6f8e1cab498f139fa0fec566c46b1eb5c883eb1b4e77a686a70fb32cbd0dfbdb6f5c0d74d8701710c161f1788ed9828520a005c97779ed492b412091147d775509396c79939b58ad1ee9f97bdff1f66da0e8c3317e7d5b6d725dc443c3c59b979aaab12318b5808f7fc3ec7965396870801cc45ecd4fdc06987db6785994aa915aeb817299852eae1216d65780e0fe8a1887346239d6bc877602d2d579f7354d4f19076a3fdac7c8acc8fef8fd76f7bc0b0b57e6935fd0fef0095588b1af5917643facb61b4c8eec51846b12d685570dedb709bcf54c473032fd0c0755752e84d68ffbe7df447342c8c63e57e9aead818ec74ea65249eea5c728584f894a6185b429a50c476910248508b39dc1ac0af675a2c94d53d11e3ec1e2cfb1f0bfc3b332b4627003282b0ada73f8421c4b815156cf18693a04c882b20a28bf0b793a7d5ff6e1b5b150501107659308751dd850c39d121bd0c3a7625bb10cfdab7cac4a678110978a4f11594dad9e7788af6e1adc0a8bb6097c2c6b4bc8a75c19d9afd26182818c241d32e6c9d12142d9752b57d8235a462735180658f859f31c6601ddefb32232f44851626c0e9da79e0f0d349c129945b95ffd7c2b52eccb20ecaa119075ec2c4719c19433e1a6e6ac526daecdb28ff5ebe4d54e5171720b615e790293fdcf4907509a86e5218349abcf2523b461a1a87cbbe0c52e32331bcc28e27a69932073d75d2e2dd2e735081b18c9f449107164e05ddf02c8d32d0cc9831614aa2108a23b1f4a500f627b34e78e689650ad8f8297eb914470f21865066c369a7061eeb46b1aff2f74c096a1d92fe97c1eb62d43e5ea8422b82aca57ff5d69a5a058d0e1ec19515267bbf3c96bfd0a569a2e79a51a40f5ef94e131da32acbe14f8df227a0d994e58448eb92be95181fd6a1cfbe959ed87525ff168e8a067974daad351f8bc911719225e355308ffe97663df16218073f451093baa8c47e1450cecdd1d675d4fc79bd853f4227a113d0e5a49d0c07a83a5d725a30fdfdcc29bac2b7c334e967b3f1420820dff7cfef3e66dfeffc5a36b91efb8e19f74550a805dbd5edfabad2cae21ca3c25967c083a911a27acd548232101ef86ead9ba929efcf8f02d97d452bbdb0de63bd71d3abc8b8b979dc3cfc9eef7a6feeb33311499ae3787a1c20a944c2a617bf32169a9e0bd7caf733bef31dbaef14907de83da114fe4820396d60ca14ba5c5d8d0666c4bed6bf54a5f091ddb85a63599015c2656c7250c097efc6e3dff76b0c67d9466d5bd65965558d59fca0ab6c4d687bbaff2ca5f44a8f8a55fa8896f0c77fab5ce0dc6fe5329362ebc8af485d4183802ad8c1aa0efa53ce14341522a17e8a898ee7a4fed384550dafb977a713fda6816a088ed8ad9d5df94d316fc422f993e9bf50fe488a11db2c460cc41abe6bf2133cf407e71eb38b5524f332620f91386d200527890ffba8e84eac8fabb18f400bb78bf602f39c59eab7b3228425ffe520a317b2898f1b62f777072c4da536b7f0413049fa4513072dd91bab13251ffea08e7a2b487297cc7cfa16faf0da14a420209fc1a4fea5409d758c797f5fa3f8a43dfa5f9cb435bd3b7e6a85fcadab08a7162584a229cb24b6b23cf4803b9e8a163e89b910448dfdb84fe6e0770e8272614bd20571cd5a038ab246658c225ec7748447460c0e1c53af6d01f387c6b196683d6506a2df00ae66dbb27abb55c90cf7c779bbc16809163b21be879091b77908886210e14451fd4a15b67d3a618147365824b7d49c50bbf14f24e3114cdfa509a25aeaade27c0acd533347d42aea0f17340d38b832d8d79b827f305fcfc63b601e28e928cc119bf3336df39cc6e3f84244b177cef3cea00385fc07c8b919718d7e5d64a840b74b9d2a057526b3a2ff31f5d8450f1816e47a9d66c52d7226fd66201dd81950533a120850668e335cda4a01a6499b93c7f4d5c3d41e819afaee3085ed2ae5f3d867494c6595dd15423951a99b8aecfca7e4e106f9d93995e7f755d4a17dd0cf8db8e95e35f68155847d7147c3de7a4b278a54d6ef82f88a68eccfcbe560147a8abbd0e259093bbcc7935cf767e5a51ffbaf325e1efda3f36abdd68f1be8697cf4bc3910bac44cafab047fafe9ebf1cbdcf48ae6f8f79c3cec583eef1989fd6d8e3d534024a69cbd5692d020541eee6e729e29d424e4995841e76d6ed98b3459cac8968ee74b864166972daabe6ab64395a23790ced9802acc375c20a54baa56c6ed76489870a5ecce6e0f5a86b7946fdd61bf93d01d62e3e217a1ddfe9faddffae12238ae776e45990bd8589a9b16dd0dfd2c950954183aadc0eedcca49922077bea506a6a3a1134d2dbb214b25e436b2a5739f14ac303dcc91b574ac496261fafffa700edd5637ecb4272ee8ff54a41e6a27d5ce8146a22ac0661340b1d1c89475b22afa47a1003a1eef4cfaa44ba317de3ceb924579e2e8dee07b39dc1178cf816126b1da2880d85fa8c9ee570deed57871e6b40fbbf50653e6abbe4aa534b148b417f1355c9ec255352bfbb2b785ba1d85ead3840ab4fd8eaa7befec4ce8799717a4ad04460b6d99c646d726a36bf29c1a48f4e9bdf087ef9d4eda22be73719c282cdd1d38450377d65ece5003873c111f498adc67e4edf1ce31270ca297f9fc6f4fe66cee9c936bd327d80167c66813076fcd750bfaa6afff8d79f90b8b09e37d9b5e7489daf95417c857cd3dd9faad6366396ceff74d9f5bad7127af71731d6d1a5fe54905246e45d55ace7d0ee6cff9dbc70e360b339e4d8c0204ed75e8666d965acc6cf44c6a04dd917f2446d2a904ba53ab1ca15f2b349410d46bf2f6df2af4505567d1a17ca88d8c2d0d1f417b4cf78bf7d008f2848bfcd75dcbd17e1444a08d3e565ad10f73c132ec9fcfe4db23248ba73297a2e0bdbda4c8ca91676da4de5120ea3560c92668a5b3987a19e487982c64920d1d555a868988f80884809a9c160256cb59dccd18fb0efd5919e289a1bf643526475250ad7c5b57c645e81fdc971f5652598112e415ab4cbc37c89ccb87892c750e66a11efb974780c73a592f1f3b82af8eb89b374e9b258067ce52e0c0849f624fb9c14692a6b47b0c33a1712162985e15244916ae7b39f890359ddbf13aec4f66a4a4868b5d7960c161e72adf9938d02fe54b1f7548f12fe84746fcb08768c14c8cef7be5a255cabb693401a71b58e4fe44e9a3f3ed99b48942dfde66b2afcee69b94ac54c490f09d7c773025edce11c108022176107e2b4c8a772aa9a4dbf0b06b6ac7ac6cc1d9c0ce903a3f7079381daa1d27f5dfed8c46a2afb32ca7ed8618759b7ae434f4cf0c6095c528e265173165eebce4c9eb5706cbb1fb09579e257b7e7ee891a59f9d72960eade6a2082414fcb546e5e625a4537bfaa429e6a4523341729c1c4204799fa11e942bc950b6881e618ba50af9c59f62f72e0e6a1cccdc13c97b52458ce5987f4b82f26f5f8988599b771e1ba49f97257861c6d3169b8fddd78c63b897d8454af26914a3f1504bcb229300a477fdfb6dd529dda5182202f4ddaea2d6a95940d2a99ee7eb403312afcb28af516ece17a165f98f771e8e4e73df31a9b1e8259f7a162e851ddebf50c63af67912a3b9b1e4063a313f5710369de1a9e09e55fcd23da97cb33e8af359ac066f71ccc756e278a4bd15f5628dfacec11ffcf654425401f8396de9a7087b9baab91f3b4c64fc2e50fe623fa6d2e1ed95cbe5c7599c92f77c4ff4558e199b0b7bdec3fe495d6ad9de88627bce66f83ef1efd60c9dd600026de7ac5950b5205553b4fdcea26de2ad46d9cb48fb48e119c5e3995ffa5087501e408a1e2b4ac5d453c8d5c6e3c5bca0ed29b4f56afb4ef309cd7ddad895ae491ba23e5d02b2269aecece5f466fd731617f21296381d30e970a828007866dd28b3c49e583266d5b0aef0e150b1fdaa1475cc891e782c630ca7db4cafb4c994b8d1ece379e8ea1854c34339bb361c9fa733be8026edbe637a4c9570a7d573e934c0b2f08a23eb93554b472e1315f20b10cfaa20e44da47e17ac54a2a2033849da12176c133d9f509de8616c57d598070ea2f8959d0605744e67850a03745925379a173931825e5f931995230a915e43774b567a44d86fdb35110d826a42b31be34b1a2318b042d7d4a7e1a19b379ab9d0d3b8d8f3defe1934ddd8b6952724e0f8c263859b8d8be0c745346ba2e35d2dbe9a8b4cd776ca5a659bfed05c07bd1284780e70ce82cd47faf943ed89fa4e306f061d2df58cce1c098d2a12682f8e8e6a167f4e7a16976542d16c35b248ad7a53d9750d31f546c64a4cd74a393a94c1e8bc3cd36149f7ae3010aabcbb57e79a2bfb51d44c9ad2974f200fb9b0ad400f66dbbd97cdab3296a67a014fa0a0dcdb6b3674242a1f424ce1e3873903c95f8653d3b73e3ae346aa98d6a856a27284c6885d14bd5c00896bdb979c6f645ea9e04067b1047b0372494285a3c406818fb20592f9a569e04c31d5d2967295f0cde7d4ffeb298473f27c5143c702ec3b64d83e6d4a83f210896277fd93220fb003542cae31c0e430c710314a852ec676696dd4f239fcd4bb2550dcfda9a5813cfb49c323459c48e13a84745386f0bd34fb7cd0f89f72277f34960400a534acdd1423f27da7d415749f1abf925edd9d526d065ce67db530ae19fbacdc880cebb15fb6dec62d77f66f48a48f2b19681040590c249074a06aa24ec8204b367a16d36ff85585fd960e3601a94345d5d298c8393b6a847a376892931d65b38f460cf086f21c02bacb43d82d7da1dff3954b5fc7505e945beaca9a58671c8e821e7f75546e28477cc7d23b01fb6b0f9ae41b98c6d749e6008b0f3292113f222fd70546cc8029326283a45a5d18c859492b04a51a11909ea51f3396a54b2a8b841c8eb897adc032b149346420dc86c00444571b3d7d8515895c9e0b575e3b7847c8327eea5223952c7e8e759dccf02ac7e4bf79d520e4fe3c7a62d796bc5c5fe162516934c9e38bd926c7dc9fa06c1bcc4b34fe7d9d81174659f4e6730c3a110995576d42e24f5b8d06cd624ba84ba46b1942a6d77bf9438841b9a688093aefef151d4809d6340ad31f4a1f90421be77dd98f0dec7dd79780b3e038352f4b8a1a27ed38a323df340a0221a60e323257c34ae73e061b748af6b5909a5a8d0b76bdd0136bf3e914bf2cf53fec580c8b54c35c2b8defa542b8b7120023784bbd99029c3af4bf54c41cf88ebf6e586adeb02fee91393acd0b7529dcef8fe5237a4580774ffb4d32c6cb57e6299f3b0ee430502cf43086d3ce55f8f1888b4ff82493af31449838863808941a167c7afeaec06d1f55205821eea7a27011aca5ce15715ef2b7493d5740138c8ed88829cf481d4e45a6814d69be96a7f1fd8ec8fa6f18db2f979d42d61fd4fd538557854ac426aa3136482a2db6ed98e1e406a4fa17a3e3d647e9d0c7d37d58fad86430b04c5b6cf268cda606a100b6facc3e0344fdda9f4a1d76adf441d55380bbcb168c872874e37a5c8a0782b4bfe631e7e0c98d47d3afc0bf8885c626c868ba61d29448127608db9b4c701b53f9e98d8d67c357ec1ddb5da0d6e5de051951cd894407b38bbb07092d83be9a4de319ce8ec587cd977b54c1aa594dd3afc69b20877dbed83d5aa8c76bb62e4036cca65b02b1d718539b9f24c67faf2a320260663c7ede0f6bc4999f040b5f06d91ed10ac0eca41eb14c35f317bdc3f3a5f1cf22fa2d2484c7d9d1971f1a0cd1b93a7aca1ca1b0b6758878df81ee6b5f80b96876c654e7170a525ed56fa072268a8984ffde716a60ef62ded7b83d0065205d03709f47c24f26d4227191258384526b7865f43986b1b207092c5c44d512a40c0472e51616843bf8ff8dcfeb13becb3fde13891bd40480fbd38a826ce3aa9633703c0ee8884846f7017dfe251bf42c1306d930bbab759444d775a8f6fb80dad75b04ed89aca27c3a7679f192ab679517175821e014c8fa1ee07518d4427b621c82b5fe3a64168eff6ee1171850abc6535f82dcfdc5c6557e90bb1f958a25789591f76dab9c922c636f28deb3c39fe4eb43dd3080b15a800789d630ca8af29b99fb7e43b908fd9f8362d4a2dc11e9e5e79e26a2048b2d0fbe77d6fadb153991c19b5e4fcf7259b503492c272da635495dc310fd0e0b17fb0f61bda37f7c7b0dbb00e2408946354515a1b0f9a5c9753a1f60861f03ee3bbcc9984dba4c06ef4a636d95120089175206c649d41c5645ac90b59f8976b975f7426e854510d2ea6a2833c80223f8a513a6cde424fbe92cd6803045e11f33d75f4b00503492f75026c520fd0bdc091c488927cb47726f2a2d5bbf8707520eb6601c28d31d4b558e2e5de1ff38957a8ba9f8b530bdf8a7c381de7bef98e86a640e4fa5741d6c71f4e07d6ca0a6578357c6c78369336b9096f1cc30687574704338c66b6eb16a3160da608ccf299655f98be77299560659fe41cc3f10909165aa0f75f161aa199ac0593f9714d595af6af1292a43d8f03d5f62ac2927744f6d483e4f73374268a1d4deacae9fe95b16ee47548c3dbf855df8a9e999a4a2ad18a13b6ea426b2f9eb526c21c2110c33244c14d0d4efdbf5bb093f0477400e7b378e40e250a9e0364f08b1348b18027e1cc5606d73edf15f90c1c0e3ed81dc60eea9a317ae833ddaf655e5e4592ecdb99b0d9d769fff6925a500248e2708316b22fa0828e5a839b09678d089b45ee1ea5255a0e4aa05cb8743841d44659a4fd872db1dbf6b0cdc8673a92caa7b60103ca3a9514ff4d0365cb8a3eed22e1dec558bad87e606822dcc689c07d799ff44f514f9a992f4f94344dfbf09de5455a071213fa59730e09be2b5499887af271ffc72855a0cfd9e4bad55ef11894318a5cdc9cb38f4aabf763181846dc5b58da1c541f74d405de8aa47e741fc0c1be1874a8182034e9e82814d18d901162f3f27a8038e436b728659ed6487db29fc44cfdf2cf8cbd6a0091802953b3ded6d84ff948c6bec12db6a9d9978d26e524db6caf298c9539ca6a30a5dfd308d8d6757fcf80cdb3cba620f0d9cb7867e81764eab7f32ee8174841556bdd2e7fe74343d8b96ff180dd52a2fd49210028602f6450f978ae52a7e5493361569f6e48689f9862c321bbc3c6481bc6f974724b85118990c66d35e11bb51bd196cfd4b837ff397c5239fb8fbc2360ec80c2d6ae91f5b457d415606c7fc9f4b4e2b66cc8b714dd9b18f078d2bac83910260f1f53070135f47be2d2c6429e0e498046b5a3b133564f1a4727e330b4892745ad0a6b2a84a4014d2954b5984efd93f5896ec86173c70076c82b51fd04ad3d02103f92a16c5405ab66d801d2a53b473dc6dd5036f3265d00b1f6572ebf25bf6a957edc5ec918f741012f93fd29d97e3ab7c5accb215bd04ec8459a1ae052fbcfb61ab9dc16086bb116326ab3583720f63263720d41e6d0259634931effa306463969d4be2ec81b2d58e48ed5f055c0f12c4cfacec241046c65cc99cf6bfe021cbf219525a273b8907bd0a11a7e62a81f3d7fa2695924583238f5cbdae5ba1703b0359ce013e07f9932b2c1bc7af7aa22532db855c7b75637e3698149bfbd191befae861bcad267331d446ba3589838b9d83d8b539e2f8b277e83aff5b2c917351f4da900d70b827f956aa5cb0fe682b1d805b0baa67acb905b7ec10fe36f3cd02131729b931a5c165318ea81c8820203f1c86743b6f346d0b4141aa74b70b56ea849858e9c5b4313df22bfa9bf8fad8e736f283a368c94d6ef632e48366329bb0a7c235782a7f6cb237a472e23b85a3e6c956d5a46a120502e344bb2c3e723f02ecdc9f4c2411c1be8f504bc887894909034b489bf5357304d680a5fd4aeec4e6cf9354db16492f26a415dfac9fbc92e9677ce5ee95535b3c6bc4aa3d1ed34b990d2b70e092fe15a71551395422de5b0bca1c5ffdd73d3d9f462c65b0795fb8ae2e2f755e0c2ffb3d10484c83ea74d376dac6487a18d30deebde68af494da710db1b3cad9c5247bc9fcd3424039bed93cab3262c68ce34c20fe4bedc962ed1a94ef38fe2d7d01abc3e26b7f1566ba8f8678cfd89367e2be6566289f1048f9e9083a962ae91fe664e0fb375b5da0192281ddefdeee1d72b1a71f6c704dc3bc5c19dd1f3f6cfa2331acc12354bed2f2cd4660a99b7ba5ded894664dd9cd1a20f05fb113a229cb436fbce0ab766b1104f72c4020510eac9fbd429d01f467413f44e6376609d8d0341952940208012764c9036cb19622e5ed56409f1d7a32daff049cb4cf22cf24d1d6ee4bf318257a3c86f969265908333f1c2a4e7c3559ed5ddaf9742c193021b004fc2931220775d46d4511bc16fd1d0d0d381d15727150af85699555edb93a89eb18d8e0766fb27d676556f682b26d75839ce5447b17cbd6a88bf8e70bbaa4e94c3c010390cba53867ee300449740a426c8c97ddaebada08f1e7f38d08fd042cb3bd5ecabd43aefe575657cc24fe07ff50b150c704587894cfd4f7f2bbeb88bf635533f09397590d6baf6f967435377069261f56a900dd6445649043c226c949f6c2aac22516e49907e767813cdd85d60412c1ec1f32d1ea227d43a890f3eecdffec75da8924ca5fc9929a96713613dd8d2fe4476f6a6d43f027169f513d9a6f633d0e681c40d987b2c991b8ae763218bb52d5cfae9eb70d436c891704b4bd40b7a5a818fd22c6fca12f5f010e27e6ca2eecb1cfc4aa5674cbfef950961f6fa2dd8704c7a34c17514937c80996e718160ea885210c96813a4bef28a9d0ee19f1ce8f2118464f5ab739166fa44b0c63e69d9650f625636b23bfa07d5c3f9ceba54ca4d7f5dcb57c48c6d60571f39426132a09886cf4ca078b0180eedbcf52dd3636fecbcf393be5a9771dd9e33050860a1a4b2144bc5f9132a8810595910f17cc98a3bfe8f520d339b9a632bc25ed43568ac1894fdbd84e13a78a7dd83267708c7574032e8d82710eadccf5e703426abaf43d49915107572c2a4756f9ec6bc6ab321f585c22cdac1e7b6724bfa2e5bed647260604f71a87e7a6e28f1e53978649a15fce8fc8fcdcc39e0cbeb04e8c6aa1bff1673925354816f16b23d766eba3887957b2c66e266e666b00fd62dbbd6dbc37cc7484b8157c80db03d29a17e96139f8d9c7adae6cac5d89c8b9cd96443d4d57c7f50099d9a82e190c7ce5bf7d6289d907d43a2b0cf170cb96e7e68246bae9b1a94a3f2fa4c39767b1747206ca83d4441987dde05b50566636ef5f669a126d97632788df08e9f437e0e86f0ce6fb8a31e09af2f69e58b378af2164fe7e649175a880659bbeccef34898f0a9dba27f300c88055db252d1cb0e2d2a0f3d92389041777509ee7369580cfdd4261a6a0f07eca1d1d4217b8ea2ac392eeedb6ee02a968eddc2b8b6f1fa19a4fc9d6789b6431b2e0004c7614fc0a968d89707aa6e3acfe8d0923d6ea7385ea8e6f1e25f7999945f1389c5717616967e9f2ec6407845697ac6972bb16fb6616165531a253944995c5559a6106738e741d7169fba671723e62fcebcc535f46a45ec08586026f4799fbb124baf15e8414801363331a012749a34384b50793eac7f0d21442a43adbd8a659dd0b7a7941c23a0a69f73a37d8ab99afa84575f9728f40371b7467565e41b19869b69882d8187f88f005038133f7defbacbf57d8f96c69ed0d2cb56d9b4777e24d36d887bd38af3d8c29aca6c96b92e9e21f33239982dbca2e643eb76c25a7d3721efe39493a13248daf5a44d07bfad22af21befa24ac9f276e29599b1cb29a55f7076752f57118c3c41e8e2b6c2aaded96f70feee948947c68d7be76081ee567caf9a17d42ddae7c6a05cff9851b18f2c1748f92c25ebd2e7d78f9d022763e4ea49f5806a9c1e7395bda51a5f8d03e457774752bb7dea5e19662fef365e857d97d865e03fe3205c656d1c457bab187f26fbe94ad679eb2eba00e609355517db6c2f7e2ae68f68f7c4e779495bef15f7edf0458d935590042f07be37b81e82f1a6298560b0d9fcfcf0fceb2ee67ba0e0ee08ad40afbc83d11dcc293820f3fc871a8a362f1bafaf1edc4e9b5c68797fa82cc9d428e0b1fbf5c016e113cb57ca8e2eacb03bfb8263dedbddfa9ec5878dfe6037fba20e6f3c762108844d3705abb4e55349bbd10f7d8b560c5a62e0db4a95bd83d11a8f75bb1d9f91f4ac37354bbd22448794f2486590af45ef6237f9d9a6ff5bdfef4632a42dc4395f54650fe3a7e6370356452cf6f73105dcafa269cf42523e62f56b5679b18971ef7f2b292e99dda58d0e140f9d2a344638d931c5a0295e0a7ddd2ef7c7bbe13fa6bf74750d73c863e87c84037faf2f978b31709c6535159e4c13917f6f862e570f8abd37b6c5d7bf32769b2af77976d9434155aa81930f61d73e6c1b009d427caa1e5400431dc55205ee0b03967f9a1bc55448bc00edf9a1a3c199b54218068763be361368056522dde4c43044ffff161ffbda0c02d8609d1314075887ac4a77be963a5f66600b4f5a5466f2e101aaf365a4f14ae43204ff6e01c302eefb8bcee160b8eb0316738abb8e9343d0ea321e8c68b90e891ec5511db33d4d8af66ee6d169d7f7f440cb9d8585687c2d0c9495a2e0ffaf3cde00d2504bbf41fcf36b3fa97492fdaae17662b79c0be4b5ffa3aa6e6aa40fc0e5d269fd71bf64f36a4462ad488ad4aca7347d420e4ba145abf31a1ad0902f16890abd345a50e35df0985fd6d22fe52d9370ef52728d06ef7ffb159781aad97238b033ca598f28f26abde02415bf27a4d460c25631ba952c186e4ff788a52fb6883179b42f0285cd9ef6b5eadb7251375ecdd7cc4145aea7733b835a7c982defa2382942f30d446f25a7eb03d3c080ebf0ca43fb5fd7f12c74fc6c6bf324adb6cf8f79c866e8bf0ecdb2fa141f2b310d36de38b85910d73762d313826a2fa7680a3b92a04f09bff8da997b269c47b72b91257c049b9ef0de76b70abeb322bf9e6e1a4732a1f5163ac8c725a7b8268c169ae98e8e2ef29b8d332b097c544267b5afb110a063840ade5","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"12345678901234567890123456789012"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>
