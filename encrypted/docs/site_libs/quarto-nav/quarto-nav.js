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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"913f9cc0c15e56b9c990dd0aa20790db032a336c5de4e8413ddb884a0e59a4b76cedc953eb057b93bf9de67f617f7f6007adbe37dc0bb45d75a91ee04a9810ba83bb5e5f64494d2504c8d7697b53b6ba51a15e411c990ac49e76d345d2c401a9d3de8e67d01ca6658bbdf7ecc43d47f9038d184e92264abbfe1168af37a356043ca4fe6f3c566df0ace258ba8f9c9ae514b81a3ddef78396420cf9bab4425ca7538d1f5cd60a781b9cd5fba2a4782845b08d1be327da9edbc7299e009eee10980551cd8508df278a1e695ce837394387f4a38a5ae68c1bcb038b74aaf872d72583608827a06fddb4a0c04a7dc5438dcf38f509cfa339408ca656b124f1561993606e280fc5bbfda77a03c89991086088c22f56d6a49742733bf41800604f22e96273241dffcce897dcf90b439372b2ed21ecf53641d6ebfe8849e728fc8ebd72a4bb6846c32a2658687c60148b7bb82a354f369080ab3ad2bccf7e9355ff4c6be3076d2a19b76c546c7d519a9479ad25527975fc6c5e84d26c1ece4b7b5ecfd1d506feafe50b12fe218d9cb89de8946e439d1cc7424d373ba251d63eec217b832e1f0aa3386cb3b41daee390137a6e6e34c8111cf6357190fcb178063e26945f594d0b1ba6f11f4687ef16dc65221a9ba91e0e3f65e4c452b2ed306840c37c054036ef39f72c645a61a9a38c99b3d5e4a050abf7565fcdd882c167c4d88b36aa3d3f6f3c787a911adc2e6dab2a6198530dc86d6267773d59a71be8684a625c4448a25c72c4a258681a1d6fd2ea6663d0f62d5cc80b93391f3996649495953054ede678ef45226e55905507044cc6d1662dc837e2ff46867e914fd2679cff2065769e9e34a666a7704cee99788fe1b886227c07f8a663c8b3e7ec5f178fd030eeeabeabfca0deecf239d2dce6c404540745c4a6c011f82c9ef3c94076a249d847e369597ffb5b0ac1ff3d1db5d07de6c3b5cc5260e05cb166135589942b6c92043fe6da8baef9bf9a3815e793f0fa57cc20a7cf3a930dd5d8aaed533aba43e5b1204c16fdf2c80786b03f53dea0e2991e4f02d87910156c2e844788cb08fee13bcc0b4d17ea9e5f6d6a3bf4b72c23a2aabd9928b6a5f2b146035103aeea757984532e6fd38ec41b24f5ba71fd917f35a21608ff0c3cc3a624e3e7b4f9c14521136e7a23ab4d591c93425ebdc2fb954d58fb51b2ce6fbc83571a4b27174ca246d93449b32a8cab21e3f3544376c5b0a5f602c276f91dfc11417c0e3d391838398be92a9c1bff357b3a248ad50b0865f16ddada26c611e927b6838e8b3960fdc1e134bda096715d2ceb9ea5f7a859cbe56f9840b27ba4193f84f50e0427020a4f74d24343b065626417a19b226ec5ca43a277431d21197615760ce7458355ae39da466dc53e822bfb3f0474871b59fcc586378c5b4bcb026565c5596a705d56c1ac83833ac361cdefd814ed5345fbcd74d3df5d2933c89ed549161058c4ad472a74d41bbc40e4073569b942dbdad53e4f36c0c45c27dc3f4a47f19857a1b20cab729f4c1f65516917c8a7e0e083467da86665f93461eee51ae7de436f36d897e3f17b5a9eed4fb86f60430771989f9b8764d8cc693d1baf17e877841734a7ff67409358346393961c0841b59b0d5e59b1cf79c3249dd3a0a5abbdffce1203914b3368ad68933f3245bac7237139451cae83115d8509a231b58161e477d619d48f6a9e0cc581ef0f9e9f3ee69fe53da023cbb0d2002a120ab2785ee104c9e1b16b7e2b98c9a85121a912b67ae622df7fd50d605165aa90f9ddc5237cd5778879a836defe1b13675956b88cf8c894fcbcda9d2ba23137c0ad843b831644d853a00a212328bd671f90c38a1326682d675009fefa64548541cd6fd099e6ac20537ebe0fef14a8796bd187cca9d4ccc0ce4fbcc677754648b024f66fe488f3b159fd301c70745b39a53f0ac37e1bfa47603488253b3fbb5742a5a5cadb52e3d5fe3c411be7915f814f977d6f7cdac6bac204f3a0f8cbd442c6c50d17425bb30f4c21389d311ce6bb9244ad979012a716496f6fcec50127a01d1e615822430b4185e1eb0c98ceb5440cf9289005bb438a7836494e2b02f8fed55f8f16c40928eec985dd95c074a1b23d8ee24f39ce4837690ef6639a028d44d9f976e286db11aa5076cfc809b2bbfa2800d963715151a26b5ef737ffdbb207f6344e30e53776b226c42b460eb0a96e70a568e1e74df9ba9c7e8cdc391514f619297378f20e11e45483097a18d0e1ead842eaa677243b88e23b54a55630f7e89a1b0ee80c90fa7d611f888832ba26853d3e03890344492200dd0aad61aafd2175c7c57644fa23e58403e96a3af2f6b71d78b908a0ff42f4574655711f02dee558219049b91b5d35e7eea84788b36f9e4e032bd60f6e6677a1f17406a6a6b175cbf875e0d8ec0fb8a8d2efdc907f19acaa177bef2f37e13435f0ea5b022367a2d9945941c7fa0f55269af358dd512d8b2298118dd4344bdc9faf900709ff87a49edc0f14abea6240a873f397c628c0019715bf207e09eedccaca18235207298be560b56bf1737d4a1263a8c4c9077513b9ea0153a725f26a0f61ceaa8447d83b1cdd495fb436a89f772cb69925302c474ec0cc11586cb5f256fedc6f511998a7553f95681f68b41f681aaa6f71b06e4008b8bbfaaf75fa8dfb037b055c8e0a5da11653b7014d71110c26680283d0a4ccb53b948ca51ca337dc6079068a43a1e3ca00bc4106b7b7c2ed682d2ae718af49c4c108e65d78f90979d47bc4eeb0961b22a5c8dd6818f4ba4b949aa559100deebb93d0b39cd346774a5787510b4e57fde2dab725c9f2a64487c3b9e819dbc520da52f7f6ce830b9255eeca4e040f5e3d69f318b6f2f59626eb793e39196bcc996f70f00c61d712b9b812d6a410727ffaee0b48595ac2eaa63fd86db1a3498cb547616daeb220bca985afa5f7c2576593c2b7e8327c53d270daf77d9d40b26e5b2e29f93cdea5ec70094e067b32851b20ca7ff5bee40e48841fd5e16974146993563ed11ccede62c4e7985c12e989548a1a79ac10c029b319a1d214694c4f4e504b39ba43d331914488ecf42ad65b00322361b5d8d7fbcad4c7d6b7eb39decb648947added521ef8f8f5604f9f0c776409080c9df0038e4ce157924136a160972538cb81ecfae50faa2fc2b6e0bf1ee4cc6420de0aac4361d8223d890648ab5be3dea13711fd0b05bf56177e176b2cd696e77f5f319bacfbcfe7531a12b8dbc2a02ab5b24fde04a234e2df5b37f169e1d2eb08832465a522659b7f0210a4eabd984b6fa0ff4021ef7f9d09467c317dbaeaa10b89c884dda8c71118642dffbbe9c0455bba303dd2c2b551e24e420f2df4892de1dbd9eb810cf043307d1caf14e053c2ec2cd8c01cab97951f2950eb326f15ba0859c8108a27d485040cd954ef3d21bef34e1157ae9a4bb770ea000ab9dd69612599bdf8529201d7f29bccb39c8d07af7abbd19a8224b0c176366e51d63c9f377105281f2fa9c7cda5c7881039e72035297aba99dcbcb8cf9c89f6997e3ec9dd66d72e3a7f3e615baff0eeacbbba2bdaccdbf9207d1608efb8ad363ca835c78a112e361fa94c6dabf546e50584182c55b8cb8b7d3062cc894db3feb98faaac77367643fe4419bebdc04f0bc597fc1666533501a623730ca9b509965c099e5497fbae5ab5cd3ab57a8cf01c50ce7431dae886ee3ab0c4278460b4fdccbf4bba309786700602364b7a1ca7a70cd50d43cff43c1d56cdfb1847b8fd99fb1d44767eb34d62566fbce9c6a96dafaf74e410232944ca9a0b3336ed9ff2cd3673630c0a70fefb8c50b03e44263937847fc582c827271485ab4a05b5a4eeae8501e455a25aa4c6bca7ae8e14bc5da70e3595287264ecf13b6ed99e61f89650973fb3071477046b2149108166fc3d5531fcab06040dafd90f28b3a1a64c5dc37e469cec792601385336c185cc39fd1857ebb630fb964fcb2f8de007649ad43f4539aa36702e2e9ee9974751386f7aa31efa45875a8bb7617611301f4b7212ca2380a37b513aec9e2d497b01928626f8c4ed755a7715ef3065527016aef0c297ec1e32742c9433020857e713ea506730e2d7f612f2d51bc9a7d1d8134384636cc6b9d3f9ab1abd7a5709dc27634a1f9797f8b804bde455a3895eb26a372ea4990b4a682cb128b1c78a285caccca478e7d77fe06bbbcf981d8c7772e2889bd6eb2d4b292bc2c96d47885b66d698def869e2c1eae5750430bb3bf1ecc8f8f3603ba21452e6edbb2762443e69689206f6c0808075a97fb9c82e0604345f8073f9f287b057e78753aa1dea186ed8d7a7231e1e24b6f2c355a947e0b93bdfe83e478c778090e41dfdb4ade709d6de94a4b095e69249a2454d800b4b1fe10c34b29bc1807ea70e76e423590ee8de445c02fde8f02897abb19d1ba207a44e795a6e12c0d94d8aaba851572c12fdd49927ace6209b0198be1fb5483981c48ec0eb37c1429c7d5365d1aa8c8d2f45a0e03511366b5958c0f60aa1e443f584fcafcc6c2c97439a9bcdc3f8fd04820cac42c2ee69f296a4f89b099b5f7c37a434cd26e1a134896251a1b3fac7a3f293b4babf0c60f6fad274d4a927deb950fa99323670e9d7bc8685b27c6e81a8d62e5ecaedef709da283dd7ad0e73fa8b4644cf155ff002f53d6f95c70daa006b54c8af8106cc3679c441d21acae269d7151a94d3a319163d8a9f71f1dc5a63519a55ae50d4e2184f7330032207629071b5c0cd25eb024d592477e9e8da4bf9658ccb75fbf1850acae3256e1799b6469015056e7865b5d05968c768d845fd145f8089d03b83b1da37e2b9d22d5e2fc4fdd88c98320f22327d186a5acb56108836706dc7c1903bbe460f711ded595dbd1b78368f6c2e34996ee6bd6fe2a9a1c8c9525a3e5020e58291b22986b45f73ff3475b538e532a3256bb6671f294414dc64c1c133568d4c03362c93672b585ea1a117b595adcc78e88cbdb7287b71f5432b0c34c50d5ae0486c1e562d8433387f47590cc8b40016d2851946544a47ae91c6ec7e904867ca290b37334b9c056b10a60afea71a45954c91d166aa4b16e3fc621a68c854a9469abac504017789a348f26e2467e084fac8afdb38a82005629e1da921c625a9607452c9820bae7262f93fa3f9a1988d58ef8afe9ebc67671cda1ec78d28cc46f4f1a96e63b0e04b1353146f78938e463677b0319e2760c6a93f5db7789df3de70620deb259d5511c659f872877d8ab6ba00b22d3543b75cb9f1be15b797c88811b2f8a9fcf70377ca5b021030838078a0e41f3fc4bf1948516a91fbf44086f9f22cc71d9202b88bc8c09450efeabacbd7c16f9adb586d011b9273208f93bcf38a7e7b3698b7aac26c9fb7e6bdbc50df845f4a8bbab5322b096b87db058b5059bbfa4c297be40ed9cd8eacdbe6dc57a97288fa23225fb7e40256bcb0df8ec9de1be4b282a00bc56acd7d540daebd9a4d19cb99037813fe7ce5f4fc9c05be95214acc78869b0561e010c5fe2ff1f2e1367539298cfa2f90d503ebb1c1f8912ad5595a7cb7e92581411142b9d5a64c800486f610634ec4768f7221a7c79b3c8083d1789b3bdb8e6c4ee4a9c909c9e4733a5144529628bacd9cb30ce0348e5afe489e9db54467a5d69f3ad907c438649bcf63b315f0c6634220444a6390b32b1056dfcf4ed7645aa3e4f8d3ed72b417bb214f3a6ac86770e76cbc765fb5f124ce259e2041c85561bf9b50d541b3b2c6ea71347ad1aba496d9f00562fe1f93e9ebc7534f00458f603371a8ecfdde2e8fc4b9c271e48e1c37cfebc8647653545b2ae932a684671a2f4247f47f12ae10baa216d310f5f31e7d980d910917a30b01e98b784a0a75317ff29019fe41b4ce8fe0fb06894453e5bfa7eb15694ac6203297b5280776ef85de5f838145e90fba83074d40e9d8fb0953dbcb6ad891004bf5f7b12baced30316f0289e7378970c82351efa7b10a204f3c9b54a4cf2616583a4c897cf45f97e52b1474cfb0816d5bb5cfb488bbc99c430384cbc94a0e17973f184bb4d6a413b8cbf6c5788a34bffcde566411cabbf0ff047ff36aa534f37ad0bf406689641e2f2092bfd471c11f849167fadf711e4d41da9e9c8c0bc28fee8cfae6b66857e347ae6d785e13ff8413dc37df033c3e8a50c62ff7b1bd2c624d94a1a41ce91ecc5ef6dfaf45fa69d4e3fe98a091b6a2202bc09b2359c72af844bf87d847025adfa7e8e24b130fe2e05f3a87e8632739430bc4d91ae3765e780312207cf87887178dcb84f2b74b7c6abe99fc293bf56d5d61cb5bd5bb1f0949b15e76551568e31631f4fa991edd2ab41ba7fbd4281db2c813268aa8a09a665677dfffb3a8c529f203659e6d63b892743d962c4be43da057b5da53fa6bd48b6a1c40a08f3e29712e357326bcc7212e94c29f690d188e81bc4f4d9311fb5ba654d0f3c70f3e9848ea324b45558bb13974db4ec19709b8cdb4e0085a361a674386e1765311cc7cbf6178c574cd50bacb14e7fbc8b648f845c18ab9bea98292ead5697ab6ffa8fdea78efbaac2635abbc8b1aa449b92b32d9ba8cad8c28c390c41805af312982a649312aaaf0a7a12c2ca6c4150d3bf533fa9e35ed3ee37af6430b895994dca8266df42c1b93ac9dcce77dbbe7415a29ec2808bd270d663cb3774301ed0bb484c12ae7c8a98ffd52a7f2e2b783b143a2db9f173e9e191a201b5944c709a8261e57711a9547b9fbcefb6658d9123e05a7872c9de81b7bd326ea30506dbd0159cf5c53ab74067bfe848acf6450398ca507b4cc3a64e3a73b41bf4c081050203666221d6158bce2656953ca557ad42cbf60acb489ec38b10fe1d5a13dc4b9a6137bcd7240fe2e30227b3ad6915167b7d23bce35842c4c1688b7ebe0090d2a9d0a8ff8f261879b0293307d473c0cee452d0f0e6718108c275bb4f836391d80f530137e3fce72e19efa53312af6a46955a4c1bab46e229d97ab847a7107137d061583c80f215d68a76807bdd6c12ac41e05a7110404a7b2d828be04ec655bbe4506c7c54ee8d3e717d0fd886b27ad4e8279813177a653133eecfbbee2ed5991cbedf2f15ace4aadc9a40a910cd5a739fbd20dc39f030bd1fff3b7ede9dd08ea2603d107f9f16d234c4395afc788cf5b201bf9a74f938e04d7aef7a64b12738c86b11de0b69ee439a4eff729f46f35a1bf85bfe1398980bad205d25017096f660c8205b8273f5d7daf952e64553afda1470b33d88a77380e2d14380fd888fe925f7e55ac56466c1cffe732ee8713577e2c57dea1b953e068e60e5c4ff0c4b16a31a1943fe243f72cfcb2be939f39a117f99b26f6bd7e273553c43b06fc84888413c3b003de8893ef30d1103fa2d5fa216b360edbc12a20c2230e61a95bdbd9989eb90be916d6b58d47134fefb4f9011fd10d06c4cbfe397cb046de26b98d5d63481d69ded3c9d1870b7fc8202505973b578ec8364781178137a0445d7af8688285f24fafaee7aad958a6b14ca5e1963a5c99863d482332841057f4b64162286bac43a8d1b90f153d9a2d6aa21443d03f7d410bacb034ed6b36feed7cbd3bddfa2f39fa9a4802f0889726de0016612837d834c4bee97ed44f8489d4ebf17d28b0234047b3b4cd3e796e7781e3faf3fe972fbfa38d97d38700043c9539e714ed4b38aaeaacf3ef416df427a3fe71d461fa7e3ef9721cb9271e5fb274be15bbac645a451ce76a6873e80cb650c33bdf0c940da4c35329d019c9027892eeac39766c5ae5d73f69438aa571839d4c405b837f08c82334ef23ab1a8d0f9e61c96f5d226e5b86a97218f30fffd46f9ca067edde6bc93673eeaeca5e317c7b6760a7a7371ed0998d09ebb45edb7297ba332a2b1f89fef72667f8407732e501d3077a3439640483d20623ea9ec06d77d50b1cf89285d118a86cb875b28621fe30a63a27bb2895f37e23ff613b72e46f31923546da49d383e8170ca2c1e8f8b791e3ea90ea67001ddf19b001587bdd7b701c7d236de48cddcf2a36578aa5aa302c5f1289015259ff9ba61f00d2539c73d3c75d95ab77b85c5d678ba4156bb8de27f541a41c69c2769036676921fbe7de4d40fc0d9f9673f17b1b69f3971c43105e1383e6098d3fb2b9411a5f003f832867649d7eeeaeba63fdb8113240801b82ab9fd88ef00036e8a599d1ea73a944a12b48e18c20ea60784c9ca12416efb529be56ce05ad365b75dd27c4d3355659b46cce40bc94074446a44e3ddcb34103d72288db7bc5d1ca85c965aa7f4bca6731cd0e32ca20f46ecb6923cd219f56c0ef8605c94e85464d9fa53ba836c8d08337230a4120e6b67f9ff972b78b0e27afa65524dff7461515877f9a690d73ccf2a744dd34f497dab7423c8c6363fe847a86575a40742f878956907af598d167175d09f068179d2cc104f5d4a974c4dd13e9697d20ba7a3474de8a62e73490a77e771bee019cfd10c73934ade6859582d4e0bcb906c7d92ba69a1e3d2a702ba01bd12ca0508f716d80dcea68227738238830e19b8b50660617eb1266a611d8a251005580514394a8b8a18fb2ecdb743bba2c5f481adafdf75ff89241d0800468ab6f39d53e1290841de91c29d80df3465c4cfa4faa5d855fd8c1e487d38ac84e03671d95326f41d84a5c507b4dbda4d38d25ba90b8daa3da35a8cf09d7cab9bb341c4975330a8b8f4f2bb9ca224f01a66d0a741bd712f2d8649b8b6b6013359aecced5bfc1f8f2cb21cfdd82871c1b44136a2656df505b891ea9f3ae08a6552f609723577a85598d366fd4c9b02255afba442ee0c28ff31ca900ddb13e387e703fe16e5d1d10ec288a862621d7687159964af35ee951b05de150c2d838790b0c47eef1acb15bc098239475d9557090442c0b721ccbd22187ba5da77a71b40b7c34083f946f9166174f9ae42bfd004f4dba336ce449bd04cea97289fcf5274842c69b7e56a9f43eafd79febabd6d53a0f21e44041ca3928c45ca79877af138f0d1182b8da1e4eeea7f0cc39066f4bf6b32cf73c6a2a0a3a1ab0270d9cd1eeda4a75647e3530e5e8d88937ee641dcb2b8830cca99dda0a548f4f70db16cfe84960acf399e94ebdccdd12e82864f652864db16498048cf1fbf93d5dece87f0c1543ce751f422c0d230e160eefcc2bb6e4c42c8e95b028f02f8c194881e6a999cccb8d5fa712f4c78bd06a4b9a75f6ed7565407eac466b329a50ed8902512e2fddf441accaa9fb26046c3adc104087cfd6b1c1c385631c67ccbd0dc81ad335ef9115b287f54cb080ead18428c9688fb1164da96b5a9e5ddc0920c145dfc7873366eaf83bccb9d8189a8562e7cb992da41b0847c026b181ddd4b534e3ea7c7a20de1d5bae2c12623fedb9052b73be8f4b7b22d3bfc00598c13a1c31df4217e48f37dc2647a7a29fa2dc56d9a70ab367dcd0b0bc94a41e46e21bee7091a04278bcd3e9e40d82af79c57246ac14679f26835d9d5fd3b16a7f831b0db6adde4c777f0dd39611a2e83a7c1a6ff30332529b3658cd3730cba6c0e9d36bb914216d44c662fcd2d0fe92970ccbf10d14c39b60c1c8c7cd328b70de740a50842250b86ae8beee9351f2c2035d61c894357f2fd11ec77fbd9040f5e0571db109b720fd0770d51221461521ebae113bc57bdedd786665d1c12bbca0bde4ccdb89e81e57688e0be6fba9155fc4a02d3d1f606bf50b1f3191d93859fcf582eeb4dda4442a0f0002db69a1c83047b4e306d1bfd3ad70c042beac048849dd612a64f054d9eac1cfe89e5305f1d1eb0b3ce9666f1cdf5d2e8211dc77a5cd93ac8c701b67590172d0f6ee1c49fdf9a217c17bc7ca6d6076f09a631a44d196441a0c48fef2b8c4a46bf0cfd485e8f501e095dca0c64c027e7aa64bf175280c22f05e88feceba1977341d1aae5187f24539d4cc17cb26d94d9110a4feda3331fa28598e7545c095fa67fb0f29edcea919d465c5183baafc079318ef21e24e2b539495eee3da90b0ccb1c45f80718be1226b839a50b6306c843c5b16b3427a359ccde814f98c8504d7cfe0b52400d4702fc87501e0aa7a7cf33571b6d24d69a41dfcf214715f84e97e03163038bd2600fc86cbd776c5423dd368ea9a4c241069dcb21efd0d26a11c9522e422dc2202535314afcd6ae735021964835a1b2a3704d95315416e187a38998625215b079277c5921bf48d2c75bb39ac555fb8cfc3719b587ee3427b5e520d4327fb3dac6fed707fc350773392032f9c8efb06c937cdf8c04cca43b45b5c775f2cb6d2cb7843e5800518f99508047bff756fe79095d2dd9540ed72ce1589cd7c1af8108fe79f4a17e2fb6c0d8ad29a6507ad955902830ab351fa22e85b7e1542d8671593e71e28d4526888c5c3150c386d77a090ace52c9b49538bf9b655a10aa7056f36e819c6eea84d080ed95eaccfcdf10258c0077525f0d7c5b2bd2411fa3fca7f1a7e8ab26144ffec1021df09447b04b1e88213f050272d9d85a2f54c7e445b4ef99f80359e506478b3c9a1cdc05b83c03bab24dcbe70cbf3a8b0ae47258c758b46891914b4db95142597b0a1b1cff70e294cee6eda22a5736f8b0fcad772a554cd4c4960aea9eeded67915f2378c61b9d97d93ade1147266660b899a0f343e0f823799b33ae573956d59622fa2da8540f0074003de8d1df5664028dea9bc97d76e6fd9699f0874e1964cbf08ff9f06360af6a4126103e6985438db031cc3e179d25f2cc627bd0a29c05e06db0ab52a857dcf696b976e3551c3c52cea10216fa3eaf75fd03e5e22d5798263b74bfd1b912b2829338d0c3a362dd8751f719d969e6d8dbd7281ede7167818275fc3ed5a01f4885218c98578c24bd65238ccdbfb58af242ecfe06b710759e7ea6cc361856001dbbdd1cdbf98fc83f9384ee88ac74efc442f5a570d106c56f4be91e5237704fe43a4750bb8ecafbe40af26c65d0d53ceeb98b70c8f67acdffec3c5650b2f3639b418266a40b874d20affa0964ab77db3a543f13feb7a453138a56ed0bdb1e190b3fb8708c92b11cfc0bd016f7967242b1f77b2f1e167b9caf450dfee23f30e2defb6f7fabe45dbd4d4d783cc7c64e083dfa04d920af9db5697d41208e52542d0824705bb6b7a261c48e21880a5d4d81d7520d70a85c30eddb28d4836b4e3c54b450d6948cd1d438cdbc9e697e2d35de95350dc607a85f232d47793e3248e26f97d7ea1361febbb963f873ad0c8fa48142752aa5e591aed873b5f17723c89cbcaddbecb5455ec6294d124f0fa214bac9e3d32b0dc53a6201ce46026e1ba75b0fe8291ce1cecedfc412a9d6375515f8e332012c0ec6baaf5f721a3286c6132ebc746cae8bc8f746646a0f833ccf71cd8a838e59cb83437a105541a26f876f7944730cb08eec796fafff607c61c8a4ef5604380c13b4e07a1fc6a5c98a4fe0e49bac9514d173da14d52ff6bd6b11ac0b8c853d03dcdf5dd2b3adbf1139e6c47d349d1406b9bc1c001df4d4ec59f0d662e1f5ab24a554a5c5d371d2b493067a5b3ce7977649abd5bc178ca511f13ec4a0df5693cdff0ebede3409618fa75a1ebf5ab59949eef06655f38abb2a4b5c4456a5264e7249f6162776b32e33ba9d41fd0b16c8ce925760202e55ff04ec6f0c7235764d7e611b00dc030965c9c34083eb56596c065c313e83063e646a43169300ae902be6d21d5600252f04311a18e94997184c7a12075d70b408f98adda8eb994a81a3b2d5bca5bb78b083a95158cf1e35f3d50d5bdea237340cc6624e906478d5a450ce8ee511b32d3ae5b25a0ca973f528ff74740514177f53c3b0521ec3117d5a3e31762195a97a2ad27c169e536137b6e25f1165bf398e5da584ec17e100bc9b5b797884b2df6d16690d0263559205e76727b9ce8fc6284945ea7c356132fe2f2b2fe1dc3c70b500c1544cfdc9bae5a515e20bbe4771d033aa62cf7677fad906918176d33c2537b11cdb5f593cedaec94ae323d27679106df4de78df8f792e9beeed3f1f4371a0025529a623d40aedc61768267dc5b51022329126212b5686917236b9b83500bdd77e5a4bf86e793ddfb3d472f61a9494e73bdc3f7e370f71f1600e0e87f8bc21640c3411473300d5482986c9172d2de390a93eea7ed8829f23fdba7ef530410ec807ca21ac084566a5cefaba5b36e8dd0f9e62113b7fcfe2781fe9d14b018f2f44c1ff97eb92673acae72e0bd9b729b2c30a9dcd7089ec32961e6df6f75ff9e7648c907acee053d97f4d330e931df3f2a6886edf8ff0f3fb78e9c2e6e4ac07139fe837364e485bbe5f4c909db82e299e3bb8b8f705ace3f5efa3b67b86933a3cbbddd652ca6d5a5f18de7b3df4e0ed3387eb43ee10abcd35ab2a24d1490dddb0845f60587c5a2286a775866261bc4423c076f8aed064d0f594f22cf4f3d40b13de9a41334e9926d7c5c82d4ed2fa83220351f0257d6c033d78fbee911762fe1d6272a0d9abc3f1f0ae7602304595cc51a5c8b4b944b8df173f255716ac4c21b4c1c08299f9c441395eac0d247f6a71e0cb71cd307006b8cddacb8ac877926c66989f9c882b6f4e4348c1caa11f4532ebd58f9e7bd95340797aed84ec512ed3f2d60b55915cbc9ee1172467b5e32e85af4ba62796749b81acf65b5d2569225ab2156ef79bcae23f14e61cbb2faf4ea680cd32abe9f3c3eac13f2b6179b726485d7bd548f3114cfe12db9d15dffda147dc6c58858869f0099514f97558dd72166da999b0a315d529b4effddf8450c8de8ea1008124e5f31d2e09187e90df4abae75fc9fa4d33be4b113eb202924be3e745c453d4dc3c54a3890c87d00efc879bba53b34a2dbc38d7327380632d1b6ccfae546d73fa6c0cf5da612e5d048a28d9918f0769e3df2fc655995ec5f3f5474157e2d38c485651d58517b36640ea3c3569af957acf90a4c9dbf9d348955912791161798045bdfc21dc4cd47d3cbf6f013f34fdad2679c19b79fb9d8c49d4f27f2219040e16c279b1a10a708f289352ac07f835fb4d82a33ecb4bed31cae655b7ff14cf74854f9cb253300ff80033b4954dbfe62c3a061e7593f67bc613e0de9c95f1379bcd15d9b82487bef5cc1a4649687f8dbee0b59524c285c07cc88afe8f0b8e99436f4bca537be3745b262226cb34711b8357c1f7c8a5243476b47b07a91b7aa10f0cc07416a98fab77012d8968608dd2d9b62ccd99dc0f3589cbecbfa21caea7aa89b1f2e0f36006c57deb7b4bf9d8a8da8b95bd816cedd2625681f64de6ba2e3fe2e495c7901e44818d5bec23044a6b858dba2714a89cb6d5796783ba30110213099b60a40eb86af0c17b892c074a5ca3a99f5696b7232942ef7b8978f01169bdc065d5db079d93d92e979c520369dbf91c8edc6f77495e4cdb9221aca8aec947050da5a0fd34aae715d41dfd0f1699d47c3c5e44b952cd15f9df8ad7a4ecc664ecabf713909e20e2e49f4b8e44aa52194c7d8ab18da431a19fde170add3ebf6b99dd7beb1a91adc70bbd521f0de9d80a2b7b70d137e0d8c21fef9ead4b886e7aaad7a1a3f614ded5c1cd6e89f59059238b79267e0397a1c37dfce735b433f2e69d079c9473437f33d107430d5f85bb3136535ed5d76c863ec2df55a403c5a5c52026936820287e55eac2997ca3620bf68725ef7da45dcc4603d37bb57f9cde1db2fa6bf269fda857d09c07ca676c2067b6d7da9e1887adbdc270a94a60e00","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"12345678901234567890123456789012"};

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
