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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"b471880c8d82a124fa0a1603f386ddb021278ef7f1e39a3277a9a6f845cce9aeebc077641348e367f22e7e746a62d27e3c682501846686ad38826a7f36333417d08db40582afd6542161bbf95f0b1e38f8a9ba39cfc1d1f414032e01834af3a9e07bb780c3248262cc18aaf850ee23872c3131be46aebc082e76c3b1be1b7efe685eac85624c28a5e29a27ef94906347eeb7de138f126e922b2dcb0447c0e4d1151b51a46d631df1883485f3f4a104fd2af653b60d4453731193e9227a4fc6e9e65c80d292285a045e0a977cbc678190ba4b31a067fdb836bda9efbc02291ad0c069beec59cb9b805459061dd953dee1d519d90d5c18a329f8fdc5a774120959e59d0cb6d18a580c28b4399fa9ed3deb03810a3d342d2d67cc4221e035bf0c2c7d43ac2cf281adb9f7276b2c8e892ebb7df519ece72e5e678b29a9bd059ad357738b572c95401f18f73956a51f023c56c4e42cb8d70e4f04a719ad74e6f78b420c19e71b11622eec1c670ade989025e60ecbe99ad721e6569c60bb6288a3f17e1056515a9dac8d96bb88b48db1b3175c9ae6ff76c52856d571b67feb34de7071fb032005aee95f603c85e5b7a694498e8c0c7c8306cf57a7a4a282b3142619df9c1d23c7a4ad25a44beb196ee583d562e38094623b5e83f8100fbedd2439af32dac7e7ba9b3c3fcf1fd33202ccbac19bd55a30c0432dea2b22c6c5689e305f5c301b891bb96faac0369f58d44ffaf0a6a3ebf7098002d6af5a66f839c6fcd2d8abe9770010eee61699633cb5c36b0a8fad7b7beb615441e5916b05c81dfba7ee562961e9e4eac54772ae218d734dd1a2e7837730d13ba2da19e93a460770fb9eb39aa7871c20547ffb96432e813815f7d74963cff8669868388f239e080be831c5529bfb451f40f749b39772ec565505d5d1edeaa1af0d9fff5b9b6f393fd32543e3db8ae6a633dd5bb31d9f0b2d718d260c11df56bceca5e9771e7cf88e6ad43ddb8a6e362eb171e4673ce9f947ce764ab8bc54b92b1385b4c55aa52481d1d7ee1ab295173b975f6083a49acc61493b19d15b9a9f8b7c9bae168739391bc528c5718b25223c64df3ea0f8c02c7d330d667a0b417d50baedb86c3dc81e3f55491432b88349df51b1d45cf0234a6e9c77d51bcfe10e3c408542aa8070b9427ce716d20828932800e025ec452cae8d21c43734bf12242e142b2b580fdab133857930862dfdc38669e2e202d1ded54b2891e085e9eef7bf58452b0684274891b8b9f662b5bd033c020b751c3ed78780d7f8e78a370a034c1cd7575ac56f137e2b35c42cf5c60c2289e215a60054fcc9bd8b6ad55aec4dabe953b558c07bd266f5e1ae8705201cc9b268a85e2997979d5ec8b32a0c7d67440c107663ac7f63cefc2cd5ddae9491a05e15cc812330bdfb78804a0368eb42f758f0e31d9e120ae1a536597c47c6700678742a51b19fdc50cf087e111a2a56181c0e000c496e51855da704e3e32d911cd8cfc004f2486f89bccfc7ae5e1cb93b21fd3fe458bfcc3deac3efec76bff5a76fb71dc4d74bfa514f655b3748e33cdd5e5ade369a7de6d0102245db98a7994722c23876d301e4bbf5bc58115054f36aa4a00a8812c1f4b02c73ef1988c66eb1db82af3ab4ce453a474bd304b2cb2617308162d82b43564a16386a37cf30fca8fb77fe605535f27ab831d2b16e6346e1ec297f7216bb650463c0e74a6585e45e1ccf8d3b21e6265f10c1ca7d4e06c784db686b860d921cebb4882a91bb5f6c33ea4388109d9c993512395b0d80baa44c7421f0ed75e072dfa8488a6a92efcc755d83c96e396d0d16a372c094c175aceb2307e46af8846cc076aedb5cf7d86828f61666113ab8b363281e0d5ae33d95cd43ac8d684190cfa19cbbe36dbd53eb81130f21b3006a7beb97f7c67907089b92be0b0b09ee2f56fc609989ded51d2870937e209e25fad934563c494cd4009b5600674bd5391ed89bbde874d410365a2a5af62122a0f75c7d0ea71ad7c783b63dcc864fe470fb109fbf017fce94845b43cb581cf6fcd786aae4b7bb0ff5e48a57b7b1db3b18366a1648be07774b12e4f8934e30b733aeb210c8e8d2097be4c9b524627f3ec1eeaa81fd88cf42e3d1266502e8a6be6df7fde4d62beca773c0fefd4d6ff63407423459b818d4091bb317e7a05d81ad1fd4d036bc32a1285ec8d90898a46fb3bede0e339800ca6dbf3586e069b4f9b1aab4822f821c0a2c85fd54ec411de62775480ca8909f85ed5239c7e571d6475845ba120f16e13eeac5e4e02b1521680ec93c44aad172a36db13c366596528aca8280f78886e3f77b1c7365830106bf62b5888ac818c88b6feb80984b249c23e861290e3d0ff1240319b3c2cdad9f926f44b8b971eb81605de3d7d30ed178e54ed43bf279a4ecf6f588d869f443385ec80773bfd9ae1bf9a4d811e4c9d6fc06fb3af57fd0bf7ced480bc13cbda2673f11240a4eb9ae4201fdf6e0c42d7dcc027e22f868ebdac27400383047a85d3a4093b2745b147d60772cca6eded12843367f30c28a568dd9866a3ab140b1b2ef6244d8c3f174bbd05dad8c9a2e92a28b963ef780b1b1325f2b10664ab355ee357da9348e8e6ac4c8542690c19d14b09b8465882c96b59350d5c5597327eac505e66e984d4830e1cb3f17106ef19067dc659cec6e7f3544546404fe96c31b43e347e60a948e5e609e74f844397252901de34d08b3e2750e1b9e4d0ee4fbb20f575baca399af9dc802f5a018bcc7cfc64d1aba177ec574aece3fc84b5eaf463b3e421ba23df0a1847502b4345939c726465100167565a71920f843f72e4ac30f6ba8474e4c706a4dbf8d53a42f57a8de916aaac845e6354d769168739c366df7da91d1b6dd88843e953cd40a6ec7b1785fea63cc5ef3b8537cd858e6576ecb7692d5d61e762b56d6fa9782f5a369079f006170cc9cc3eafe1cc113c52c0d8bd7e149d3b02cfb595033fd8d877b4798cd49b3e42dad1545632b21485e2a484c9143c78417364d30a345e03870bb1194bae35a11fce350dd9b4452651e7fe94901cdfe39215736d8a05786e375a9e0abd66f0ea0f3467604f8f6174206d2779220ab9325d4f980424e44637b556885baef659ff524ed80645d266a35981e90334be9094d827245047b55afdf7ce4b5236740b20c3e5c101e5e681716386fc42bb4de7981bd98b2747c91b3eeb9375f11ae513ebbd801f38b17353c4ea7d4776bafad5ce89118904f76bf3f0be07882beb28fe93962453b166b2c549d4d766fe3fec98edd62587d450f7a87f43cfde4d3e6e0df5a1b25aebf42135da6ef454a65028dde4c371e7cf60bac2f770bc71a337170daab7fd9a2fec7bc513436ff5bf007c3c3b4a3da9f85bf164f621241aea8909c7a0326d412c6aeb3b00a191dee708a097f276454b6fa89beab8968af4f48930d9f48dbbb602fc0f7b4a1f7603a09884d66572c4c38d2b9df7767573cc2959e4730d99b6d8709a0b9cd67003ad276a11bc9e63f0e85b0e1cd6516e3d6aba6535f42446476352a6e46c02a0fff476022c92fb586354de0be3d1656ca1a5252fb16dc3b3a425288f9288ffa6826b73963a9cf951af3ed9b78d562741255ca8a5d29300ffb3aa676cb2661c7b119652eb31c182a63e2eb968ea45af40a0dac110d45c99b20145f10e952035a1d6f0afc1f808c2efac0bbe88d7ec8bbdfa6f4af43dda6b8b82d8ca7827408d92ef61cb5e34916ee4eaf74db15e0cdd6088db1fffcedc5ea78c5c77a144775339f429e4d6afc48208620b3b65285a27d8e2a401580402bf5dcf95bff3f59dae6175aad98ea0cc2eb1c3032b883fb77d79b490f5a44bb309d75b0f366f80c5eb996ed8ea775173043fbeff4492da59637c0f58dda70a25e939105143dabf5cf4c99c10ed62269b15ad5f5ebebb9307d2f972de3333081b41ff88a0afbb4374816f68b61a61af04aa4daa6ee2b211a6d0674efb6ad49786b328c7298e66f195e946d45140851581d7aefbb1af616fa1fbd4478183c07df76434d36fd027d420a1b84c5c563005dcc5305b3b9e10413dddb2e18edf131e4ae1d29ae64caa57cce24a27fbaabb352d2c8bb368667345eef31e388f6609000aa78cf837ea26fe941b5a2f71c2269c0a77f6804f063cef60efad6b65fd6728e7dc77058804cb302503c7685ab60bc5f1eb0b9514361f8c40abfdc17a258770df67da12a07620ae3472adf941e1c42bf91c071f97fa107b03ea81c5535e7ef0572263ec50706e0c6a2bd46200de69c96345558f0e215f39a829a08fa3501fadcb067a890c7629cbf7a999e73ff7687bc3fd8b7d7b3cd6fe17b241c32f3f2aa63c1dc77d50d4e930d50672af74b743601676052e1ef14fefc39f32a5058a038f29f1a6f343634db8304298f6ec19b970b133c6eef55ce112fff7baf6bfda8db86078675bdb1d2841303f70341df6b9a729f6aba40d2216533548f1c3dfa4682a275b0aa9d5004bb952d57fba02c9cd595a0ab1ab9a6d9d9f0c843789b83227980dadadd6c391ff337c93251b69962f58bece90aeab5295104bbfa663a3de0e62f783475931da7110a2e1d39680b7fa8f52bbd32f369c7729541aaa6c02310a892d719e8c8072926458c45cea6a42bb7d65c65aba911740b2d3a0d781d904f4675f12711963c0b144eea515d0a503b8850b2aafcc6543e9161485faecbd1ede1d8fbe314a2bc767c3476624acb59b9ac18bc64c10ad8f3f50cb9d75d604dc7449cbdadd9517735f5681129220a40d590c5eda1ad749789e14fbfaf915fb448aa0dd0b57a49ad3bcbede45673837cd56c641da90cbdfd7894964eee690514ed043d5e78428178c57527c6628f4485b81e7b17ecd8e49f2a0266f34d1a3e2c85f4e83b494e1e3e9454518f6f2b8880b210ba6c3084dd760508ce348bb02abdeaec910fef528d4be413382ce9c1f727b74e47f80079353d72e9df722b77c4f979edb7dcaacf08368fc03a418e7e12786f5b222dbaad9df6fbc7ee5727175eaa6e4a0ef1f5e04b896b0cc76540e1297b8d2aee22339242e9e500f070e556a27cbdf21fb8a686233f77b8a288f7108a9539a34f095405cc89ef6d6e6076550bec81ea8b582f75c8491bacead6f87ec2f420fbe979fe8c3f833abf2ace62e508ddb2094603eb514a01bcb5a49badea0b16ae71eb408de510fa5fc1c57115c919c20253af9c80d0a97112c5029a434512249dd1e54abf5aaed7a4b2f88aa252ee28a2e95b466384986211d003d909624ef7bad0ef0d87e41664c615d470e7852dd02f49aca3d1f4d2e416861b29135798bd76c43c59f033d835621575c89e8f0525d1d2a548a0b21e08973c20a9b257d3644400751f836c906d3b7423054cb60f7ff60186f34046a4002147ce619259d833a02e1e6c02ad48900ff35543b5bb2c61060afea12539446805e025d5688957b851f6c143bb0c0498f738ffdb7ef1ae880bb4029716aefe8d3c2890533202e47954a0744f155692f4273f4bdebac61f173bba5139d6221a1fb4cd0112365f47f413f61906c6d41d45bf4462d380fdb73bb22051f1436f596561c349cd137402f55bb1fea562b0e323008e3bd9709bc5c36a13d1699233aa2921f44990785b056534fcb9e5556f58616c67ce19e166b971548fb4741f256c51001c80c3b30d22ecdc23164bd8c7206877e48aff966304a34e22042d1b4734357724ab1714cc66b877f63c9710f6d6d590df2b04b0882ab5f22fbbd70442a143683ddc99a6f3686721c1742db0f4c6e768019545db2a5e3f1e51222cd41a377af46ba1238b638e6f4bd61b73bc74c524360ed740844b01e39f732617396201e8c75179c2995d97ec8925c356eeb8f8be2f9ed5ac6792a382aa5d08e9f3bf9d6ef3f7aac589a8a1ee760fee026a0d3dc50d04121e3a4e8c6ac8065ced94c2d9719b507ede5986d89cb739c03493e9fb848e7fb8edcce2a8e21249a60a017c9af0b25041ed908f22e4e3049b45cb3a779b290f6807eb8fc99c9d08451239ceee7d0958ebee32eb4764b404e9939e8f05435bb8db924a7dec5230dcdbc1b1c4eee29037137476c2c93ce6c4e4b0ffcba61ff48da8c4d71eec7cb2c063b069af377e5d81e2647ad11332a666a4be18196f4e299a047e9ab832ab21dbb87889121d0bdcbdd0bd80dbd5dcf27f7a3f909c880467fb8ea15829c5b75f996b81d9a55d395fc7d4bc8677943eee2327da804fa3a12892de35e936bc4c33bad7147b2f302f6ee84ac4963a8650534d49f6cf1f28586e35d86d666f6b79a575e151e007f6a5f5eef2dee87fef653b2d63e431162ecc639a27eec91f2715850490e88ff0e38c52c427a1192ea7a168e4975b4e384b373a5c8d48c449f569a0771bc8fc7b4ea3f8fbca00aaef571846f9617f91442d3c11a01ac25f2d6b10a464bb0961126aea2fb41a24aac16d1eb137608b22a57c9ecb0bd35c392d1f5e41a6049845170b824c337b190fc426b57ff8731a88e0653cf4f388421a68c628447c69d9291265a0e0d05420e4a6fc6c00eb31179fe16c8b766458db2a23832dce5eb168464f93fbc8477b093d56d4bfee5fc8032dc8e5894cccbc0c72d4dae814d1489daccf025d9406b8e83a02babd6b4f90a2c93f03a7483e3ac72117a877643afd44987606664c333682c0a298fe5d2f05573133d490c99bc8855c037320965bb719774ca0d8cbb936f171a736a0736f6d8ff264b4cfc83f8a6c9562de3ff7dcfa73f8f3b6c644c643c0a7027742bc958658a2172c705052e7bc33786a6619f6a408ae787039a16422d4c2291d4d70573691ad2d9b936747c9cc2efe0dfa0e7a35c9d17718d5e1157f20b91357578cd543c8f4e2d5ce2f9913431ab654851bbf5f3242df1e4f859ffb7be7d0e0cc3b97b81ea268cd0233a3e163b64a1ee651e1219c8056b3857974981b51f6fe5c122873e6d0d2d0d7ab706ef3774bf7c1243b9be4bb74ba4810b22796ba8feb7164e5c86628461d7780f2f561c5e72c570d1a6aa00c13a9fa6ac5836ee92a9127db638117c704cb037be6e435c98af833ce03fff2e221a8ab75000f89ea4b6db9e7710843b41d613e02688e525e1c10903eb88852c7c2949ed3464199e5e08443b3a9d99e6ddcb5993da7e35da5946797e74607ab73c82a63bb2a0f8f9ac2cc3d1abfbc659bcb578bfc8eed8295e6e15b77d918783b571e153207cc63cab849ae16940d4476a205310ffa213e47eb958b6d0c25629e510b782a3b9650d17e0880323130c55fbe73b2c0e320f30396a3b3b1b661f33224a9603a147a87199a3e851299224fd48fa97d3570d54a5b7c74d80da2b5f692ae5a8dc8f2a484827af0b46cca947b4f75a60b78940262b89c7c67426dd14adec51599dadb3440b7a02c4254ff8827ddeb1b3442cd52eaca1f5b3057d1781a46bc898ac527705c379a7e18b2fc86d2575768f14cee289f07e638bb365c29802c806ff24859255cb2ea1a9f6745e6c7f62c6b590482172e712791cf00e2260e55322cdd90cc77839bddc03b848e4ef085ef8b5acd9175a548c4a5074eccaa2e0bc6f4c5165db232c6ac300c23acbb7790559bb66b92b39539a38a864b58a56e0f5ddbdf5d6cc639a01d199e7b67a14c463048467e94a78c18ef3b0d4208b71b9ce6a11fc35dd24745fa5d989fb7060d84e9354fa3c1a1207141a7ccec3eabd9749d4885fad0925be8dbfac7a350b330fc1b4096b5cfaf09be1efde2279c7a9c4346e4065c4452b89e6ed514c4270ba332a671ae997c4812dbaacdc99b3ab18579c8420ecaa9c5716f5bc4bf9969bb6731f804a4265bd570abd0d6af2498977020109d52ec3633bc2cbcbb5822160ee53d7ef4f3adedfe061965a484065883ecd246daea69fbafa211bb3d60764f49b268b776639899e3616ba42ab4277af94c2c58f829a8f90705ca75ed1087c9eb47f5d5e7f213c70d5cc5c57060940aacacd3187bac776c1be30ea856a06c8d9c229ef7970d2e04ff1295aeb81ca23326c0bad851535644fc06681eafc5e8d156f7b7226d0638f1f7d5a7bebd4fa4db9c4b2fea39f9170a2bfbae48b388b680d10a1ea35f5a2eb41cd61e351509c83cfd9044a652a9dbbef4a9143a9ea50d5f1303e9b706180b07043a16c7eaa4931da4d704977631ed3ca98f5d729071aaf58e1d6d4cce489f253acded7d03fcb268bd9d901661caff8e67c344ca922d00782cd383f9235f983a1790f614af2513af1fbb5e263aa0ede8a69dac7ba946f4cf45ecb6be967eee6801258188440d9e1758a84b454cf3657ca245e2c83a285d1c6019b3ecaada076dbfa8958be14c589c2cd7ca660c30b9cb65500bdd3c0815d5576d452ccc6ced96d16b31d2249c8a0d467bdf542bee0e7ac65f25ee389e18744ce2eaa66c40e32782cdedb2c57da602f7660dc02fd650cc884592995e27ebdf7212f99e3c38c839bb8ce3c30bbdd6ae52cb2694d275bfcf2891d66696804c03d4716cd11eb84cbc9d2b8d283a596b8bfff05dcb5a6af30d2f79c3dd211a7af3f47755f536738eb55142fb4303d1a8f3d9fcd5df8e41575287ee5bb9a73a7a9a7da54ad1ceb8ecfee3d256a64bf8ffb69bdccd6fd9c7333f51538d100b80465b4dd7b88246e8ecace9502e7e916b28aa6397f579b1e8d807171181d950c7eea01126d05a6ddf527a4cd6ef7f97f4601880c2eba0fd267147cc0f54e6fb2c42f2889dc7f8be1f629e235690b46002e5331d0f05b5cb0229acc848b583acc0fe417344a0d8a11ebbca247cfc5443cfe89eecf12aa136df443017dbfc403e3e0d34d61af28373aa158682deae3bd0f76e4eae143815516fe540e4c1cced8a795b75086a7ec8f731c433d32c2d917229462e1a75833340f6b834f38696f8830e1b48e88c381dc19a0d2cd0be00eec9555da020b9206356c591b194b29dc3fa85997340c1ffc6228db73eb644c46673cca4413059b0f006ec4b5a64ff9bd01f3d1a70ee14a96ec3083f04d814a5a84b86ee5aa9a82223131dd318f99608daf5616d2cf97740ed733382d714f594e8652f04741f0a73aa4dcf0b0ce58b2846970e005517553dbb540d6c6024d5d3ec451c91d47939a752be59cb4a477fc3c0a935edbb0f26c0977cb6e114f714e3601c7c31992e15c9f8cecfb76b62f35497a33407bce79f7e97c9074267ca8a6456632443f1b002ba812854dfb5070aa5593f24b3cd3914513f87f2dea59f4309d066e0c20cbe381f9866f1ab328100f8231a0c6d5b23276f82aba2fb43bc56f7304049553e053442f2467b6d596105e317097c2e1efdc33eab7f854c118ebceecabe3ba5cb4dce9e6b28c1f179a16896a10650e7273df296814cadcd2121103fc85b358a080c8a25daf175155235293f1209845b239e4fed0c321b20bb6ccb17a85f5204e4f639987c5760564fd266cf7b467296c20a6541c7b100357fa495035dd521f124ec4ca6485d6ccfac737c6ff9ee03c150eabd999c20ccd771ef64158124bcf4480a6a59f7ec44565b7a229957464a96a7d0bfe46ce4c325f2ea801ba9d2dbf8cad81ed3baa743d215afbdd3277505a7a41bf86da289163538b173b5f2983c51f7e3c6d7c288f96fc242a2ce4d58238e53ad9d601927f0d9c4cb841fb786639f96d9489d302970ea75b777cbe39ddf409ea3baefa438dcb8e28beecafb2d55322d4d6214004e2f8d9db7dc6eabc672157d51cce6eef090227523185a95c0e8b178944098938af9683f64b47f2914dcef4bd744430e5c4170c8fa5d7dc4f05ce6e0de0687f3c731af64b915804d7a271f2db22a0df26381e8b60e3516d98e60cd4b44ca298fd0d9d2d81eee87cc8441bb466e2cdd166d5ce14f78b333c7f95177a454bcadadb5887a60837b9d0a4a0ed288b3a66a95f51b32383a7014da1a1658cad1c49e7d543e8ae8998d0da96c0e1f4a910a7f647fae4a01324cba930be3b0d036d29c8c8e92699e52dcfdb950345bed9d213e559e7a03e1d3b33b93dfe91ddbbe834daefcbe1a60eb9331c7adc40724f99793807090bf6ae885c19848d3b4b0f43e7381759fa29fc8f3223e1b88c939b45ac60d2b364daa5492f5040b502a467894dd6a55100b4f47a6399332999d87124f1018833ca12bfba834a33b55a80d444696c61806cab347a5e63a41c9937e23598e6f29fc29675df712b1c75ed00923cc110de936e560ffb4624a66b21c1777db7506097cbc8d94920bd2aef8ab09c38e73699fb96e80fe73afc3433b9ed7334a531a8cf4d97f03afff5b8aa0049350a575f20c8e4b0147c1fec49806ad8d5cc112830329d37635e1a64ae45c29381cd19fcef1c44bf78832946d0f4e903dcb5968e00118e5486bbb9fc357a557c775713be2ff16ef2fc99cdb43f629bc9324c66bf649c7bf86db41e4624d4a0f09c01eed28770e27bdbd1a5c7dfa8ecab0bcb959906be3969fa1efd092f5645e4520cbf56874dcc16a245da5afdcd42ed12ad3dac39f6036f88ddcf351693786a89fb18aeee4eaefc964b8ebf79dfa0da9dba8c4d274fc6f36783cbecddf8a6304ca06533d0d5b1f359754860e57029efae7d020f6d41f58b5fac0df7b97fe269e769c151b56d417f8169056c4bd25d23784927da2ebe60259cffb5b06f4b58c066bf07ede6dbc515ccf03c03c6794909a724ec685379820766a56a2efed4031a2cb332b5e27a88788756f391f531c3515daf9610e737b1b330fb334caaee0a536ef28f4c4d790f7fa6d062b1825ce7945543348a2f1bf2e33ea0041f34ceab74602d6bce245ae81bcec4d3ded449f1431c54bf558531d35e3d4c70cb65edadbeb8190894878f2dc97719cde0191d877f0eacc73f3d0a2dc9328be3ae5446336123790835542d1f7addee4b7c1f5ce36933b6e9d4ece183662cb43d8d381e95cd2d19c5497b5442b9dcf77aed1b0ec39cffd3a0ad131b81418819ca47dd0ea0b281a5e152a05b1da468f264960c431ddb08459dbbd178983dbf930b16c0979c2620f420671b683439d808cecbbce8300dc7c882eef4322f7ce367b7784978a4ae6bb92d7f99666ddf260c989a33ea6d6f2ce8ddbab945b3ce26de3a5754bfbf114e33430c55e6a9391204af4ac8d4a0ad6b0027b1f5e4b440b16d8ab0370cab4f5d8ca02aa71c892d03be9709f85f7cf41ae8163dfadc0afcfa329405dc5907fc68a52b09f401019d8266e0790a473cc7e9bde3d0eb9b45245282095aa79d6e2d5adc8e7cda07560261858a539957fb477688a8813223caa4cc5adb457c4f3db0b1065e904d7b66d4f31445384f63da6c7fa56aa48259172f5360fbb752855f94d10bae258e270b64958c5d12626dbefe0cd8c62ef4f7023d3524d92b632b038447027e421b1a4b5f6a5e9373878dde4feec197f9198c36cde1b1370f5675c688bbe49ea2fbc3cce1af0dde220f79b51ccdef788aacf8e3dc79b4c0f984557e93ec973980d50039c3bd5dfd512038e675e06d1a6de3f5b43b74463331f20a20dc9080ca175ccafa633d559da2058568d9c79fe56a70e200de551593222b6f226c544a66fe2dfd5e89e79f4e207df90b2c6a848f35a19a8ba011887529e6c3dc28e3f7ecd605a26e5e98d72b3b7ad6ad5df1acbcef9a87d38e37b1604621ad817524e635867ebc02f333d30fd1cf6cffcdf66ee57a2a5f2bf954c2fa1958fef2b2516fdcdd4c14d7b40f545a8f1142a3a5b832188d96d4b3a9a4b079d9173c8ac1e401ffa00ae087fd3ee3465e13c674bc4f15f0165efacb7a5c6d38bfa363c59947b2f877d13bfcbac822ac878cf4f1be1390ef89059bd8e8f561f161007ab1674d2a472688e83bedefcf0dd594ef93a9d80bceea1c20492ee59713638cc3e78b8392cae2a8e0c77132eae3345e329bd4a67a1fa67c18f5edeeaca6ef40805083f1748d827aa70fe9e07389c6702bda40ee1c80d4319a7c8535012da159d169204dbfecb8785726d072d215c7ceea9268cede483bacd7b5c2616e9c58a804caa3505f6ea24a05ffe1af433d33448ac3075fe41f0f02820c46340ff715b3e86f7b9fc3e0e89a52d72802866d326caf92dde3de97c86dd66bcc40bd05f357c43b0704e5be8ced6da2615cbf55655901df9594b1bad3ce87d6aae3bc2e5c4afac94563f80d614cecf61281268c99fb18e3127bf95198cf8c49b9733931388162c0eebcb044548830445f20bfaddf69c97fc9a13847e6d1bf4aed9a11c3ff77c9056c79854840c80fc011c983e330f6a9e09602eb4292ef59f6ea54e5e1192aab303ca49c3fe9d296641b24a05a7c3226dd68b91f13c20cee0a403fa152b85bdee4a81b95d8e4363c4d3ed71133f6a0771b056bd692f76e5a8d15b7cf8895c24efc8a4fc18f015b75cd7e8cac01062dd86a0f8ec259c490699c91d71c03f9d7790a10b5d43613642a50b0e9f9810a00ae9f5796ed1c3c9564072d681eecaf639d8f209ddac1b1a0d474bc98294437d819c4154c2cafd281e1844043b4b3fbf106a3e47e59bf36c1594069ef77d85a19a652faa11f57d2481d7cd24a8b7d0c2024f9b1cd3619e67c55d2790ec2e69a13be746feedab0a88c209a84ccd376c20415a9c2247ba0d3f93563a45b4a3c80dfe63ef92dfbc7a30cf91d358ed85e719f0e417ebda019730f50ea03c85a5bb719806804b4e0a13df85802598aac85476f29e53cad8564853d8f00966d352034f180c3173b2b49439dc1a84dfa5249ef36cd851c80ea37038175b9737e83b7198addf1981a5a77f1a46e55677395379eb99a7dcf141d6c31b14fe213407e953e10eaadbb62d2f89e4cfd9f02b5a7c24b4d3447b651688e1d1efc83b5ffd9fa82ee9e25d8a01860b7ab22f53f5afdd8b861a19fd0ce1bae23b668ea55dbd36796819c8f3d809df535f99fb875336f2d111bcb37b0b027e44aa76d57b1258a67c6b54eacd9f59382fdd07946a6e2a8ed5ceca99cd223b8abb337f7548aa1d584a2f8270078236c377528cde1c0d24931d47483d012f10484c553081a26a7d2560548432c47700a71314af3397427bf4303be31ccd99a3565701388a17127de8fcb82d86ff631ebd4608796e129ee4424960694ba55c95323222313bc28082194f38d3db5ad76aba234f03437eaabc30c5e5453f14726e134f64f1c985e6add6d05583d44b8fa5a1f30311c6fba4780b21ee9671d80c1aac3bf14941799574e9ce63909a1e8953c424bded05d4d34629f459cb55c57387d02e763bbd36bf1dffb696fc39f7dc240a0780393b664d7b3b7063ad63d4d3c5283d292584c8e492e9b6cb78da96b2c9900ae258ef1f7bcb26cc81357c28868374e60d7b48ce4ddd47bedcf6ccbff03d356a801928729f94ca6b6b0502a9482f529cdd64622a95a34b90b9a8638ace09fd573371b9b2793a2eb8ae2324c261762f56ba4c8c201855bc9097531f89f8a14d7a5aa6e65bbb3ebd3ed4e6c329fbecb1a0ab19e9c6ee0cb4bf9d2e82ee0d2949002b0abb4c9868a3175f410b8edc7cb057d0cc426a9d4fc0a5229e29cfacee7ef456cad25d137739af2e0907570347a2edada6b50853a53cef161cfe2975471bfa2c71fa07cdee70c4ddfb472203c234a3f9ac71524cd72ae2e1c8bee1aec2a5a51b4ba3772c677bf1aa440ba1d3c7b0211a48479f739b05c0bdebcc6a6936aa8b10eec2ebbf9d4385474dc1d1ba402067bdda706625547369c7c12497d0d601e0584b335d7448a86e77fcd285d93067a8e6bfb2b7dcd7141943bba09f7da1e4b4ed5a7817161ba7e180a38c5e7f1a7c2e81319015f640ad99de99535c064199c78b4f330aa790c2a637d6ff27ad3e5b483f9aeef7082fc869710113ff712080322a2b681c4335af91f2f5f06e89afeff8042d7798d4181e29b2bf5ddac8f1689fa027c1596a65c09e2ea1d3dcc9ea51ba449649163ad26d0abd4e847c398a262b8c76e411a5e5e12f6e8750cbc47734f0c79bc2fb66318bfcfbabd68f446108aef7f72b67912c8ce9fecc77b89aa42dd1c5cdde159b97096b6ff6dfe17e932de2c895709fbcef1f59bbecd0f81afd989d09ebeb57f4d3637753369678cd88428027d2a5de5ddc558713a5aa8504323ef0b454a910d8a161cd66441b7142c66b6aacc42baf800a7c4d77a42b215adc626c484f9a85d36fcbd96e770e15431dcd06d33286d45e939eda46d5e9616924d7eb72f3ef4a28fc3b0eb42176b7adc6ccafb45e137c9cea50dbf362d3c3ff65057a3af096a9b989adaf80f954c407ea5c21f8059ba0891d91085912b45e482e36479f3343207edd09998659138413142e4fde402ebe44aa1e28ef7d51012cdcaf30b2539ec6340875add6e166d8f978b4a58d1031e059b23dbd28086a625058f8d36d40c8d30ab4564ecc1d61adc9c2171eb27d7ca44694abd17fba380fa93684329992bf7a3d0e5fa6664e29cd89545bd05727c774c6c93388ce309e3697ee0f588053c415a9604ae53054896cc732acffcd5ec3c510ed248c6818d248381c87548ec76a1fc6c527370d9857048d24c83be7e1b3b0baa2d7878ef66e34e8988dacb777860489b037d4dd713c3ca1ed821692242d6d548ecb7384c361bef67576af5563d0ee14ad853d4b255f6077cb6a599e6550534b160f2aa791b3827aabcaed6f695bd038957b410978b3d6a710c303261be1df6c3b74269a4eba018810bf90392083ac055e239eceb4b4e5be3733bcdc114443c7fbbeaf7b070b633e23a1aff4f6dea0d04c8b02c6d0626b034ca82111f825e97c6b45e10fe61deeeac25ead1ada92b2c36d6de2698bea6622061ce87ac7720c5480734d9a3ba135f970b66487f4dd97ba9ef41772ba511ec7aa270b565f9e0b22e73b32a243adab2336d91f45b93a7ecf7098ffb349923bf6a0f1572da0026f1bd96e111d4aa85e5870d0ea8938937a1e574a98322b62bd5bf2fd9a4762c8e27c061872187a6613a0b4cd30ccafe41cde44d9afa11c1a62e130d979a42ce0334ba59cf88382cbdccf200872797efffa75c1590e58ee7aeb08d56634b9c048d3514ccc65f26dc07bb81e18b445794a2e89b8e7346a18a19a904537c7b1cb158b34c2fbe7dcd8fad7cc45f367e8c628140712119156b666906b9d101b2bae9f84b6b83f134f792e2cc3e5d9ca3cf94fc77d256c0fef2ac6eebff6204e8111396776227145964e4a59d5ece94beeca23beaf20f89d474664989ce7e94ff3c62e1f2f4ea1357745919859fdf213dd848a12269110058260605543a0db7ea4520c00469eca7e26b550bd38fba889fe622f685a19a17b293039d61fa90a1557ed78fcf3a66edb13b8a38f3f300a2d100fcf3150307395566ab2406636419e1af8639be610ff5704461fbef95e26fc37e71d9ae8ec46e5bcd37db6ba2a87f6ce594a45001151bcb0f60bcf01c602e92128bca2c1e0b5e3578fd88d32818ba499cb9c001ba85b6fcc3673ac4a6e21d5e8c54fa4558e0a8f64f1e2b94d5bd143399636baf1a07419c82cf3f36e183fc22bd79c402f475061fd3c396eff5c17a2d8ba290c3f9634791728cc9a5d6d12795ff56ae2cffd81a1429af179a5207fe3c42aacfeffdefc4867dc0a40947246212cb0e4b59891b99cdffd583a8eedda5d1284bfb617dfb8f3ddc93498dc59ee65bb5e64dc7bd292251c811a81c72a69995bd722607b995243642e53c791cad3a56aa8e907513ada94100234e14ac015fadd554d179a0c93837a833f825df3da687625b2278741a9a517ac99a7e40a92daf85ad352c73aa77ad29d821e48d9654907b21f4ccc8d553052d2c76c6dc67b38833055989d454f125d0c0c6cd2a3bbec585a0e2edc074a6a748093e7778e0d17e5d37a4319dc5eb7765e616378ef0219ea4816887cb01f581924c4b53d2b8fcee7aaa5012e21c55398de77406816472a238e0c3a7b82c9b0d4f56788e157eb7c5dcaf6a7e257e61e63a19ad89c8153ca1b94052515531b0fddd4a995fb79b2fab7bf8e620570eaac8563eeca33463e031b938b83c9a5b1b288356f408d915f9b77a0b30c7c759f27d3a13a7b59a04c47f34e1e6ac690eb8c0feef7f67fc3fc6932c06b57d56fb13c2da6180a30fbf2b370d7d69e2103d6c6b454aae2b1e84e555a42189bea2780fec0f5ccbfe92178db192906fe227cba3cf11fc824e7758294e3037fa88b9f45db90aae79b4ebb868b0d3abc8232c1e02222a30333d2943d4e9c272fb9cc58aceffdfde7a74850e62a3f4dab0a1a71468bc6ca4fe5877608edff35e4c5672a16061c6a96dab5d0225c1825fa3f541d7d0ab596a31b6730013e53002497d8c7f2d87ce58bca7cfe41d093b40fced7441a4778808bdd63b3694eb2999b71bfaa4156ac4467feb3a16a22598ceb27b0c090290eb97255747fde72e50be6870c5007d009c4160d097d76405e6fb2ddea38f9b09ef5fd58d12087420deda852aff6d6ffdb23a520e58ef7df376492a7a24953e56a0276db13e513a25cc792ebcfb3ed612cebff4ab2e581ac2040175d4cbe3b80dd7e3fe4548c1b14c83800a001f7cd590e20f27a3e9938c69ba199d40cfb128092a0b504ffb4057f1e45a795db1ff471547893ee846a2dbd3c25a591fa0b548713ea3417f755e299344ef4a1c5d4b1b8b0e094e095ecde1665b2c874baf5df596c0a4519f0c8fa83a8ff8125f72576b9860421f8b5185f92bbef743bd6260db9acb92839a4a1efa67050d7e75cd22cbb381c55b3fa8ca974d388c24a615e130aa78907921a75359853194603441b17d3faf288188d6faa8d58451f574a7b8257ce6e5eaf36392e5ec5e5471f25993245f100706c6f1eeb80cf71c4f1c76c096a299b5b284c8c0aec74c77c2e6cbd77f0926e23d58d52c0265861f57a3fea6f3aecf079201635de9fee796cf5402076cdbf555b44d0e0c78266f201c78e610a86c113053407c053bd9973cd9afb695f5e1189704ce5cd09f8763cb997d0c635d8270ed369d70ddb3897006b1c7974c7acea40204bbfe16274f4f335e5311918f7ead987f10b91a061cddc176bac71841e778a63de471eeed88e980bf2f8ebdf1e82d35e438685c87d58401a7f2a0ba60c331a0d3de55e790c9969b454953cb9e06f1a11dfd9bfa9e47acfefe4a52c5141e2de7223287fd59abffb4503353e46fb2124350fa39dc9e365bce3cc86a25f76606f27ed515f8022f7acbff501c9d0b7cfaf9ae7903d74350708ec6de2c3f0e9fd8422723b6727912d45d512ae6029d4fac2a8f77f2962b7daf7d7ef201852b731d3c483ff4ef416e4cae5e54e33a76863b0f8b79549c39ce8e4f22fcc10be62188285880c5f5770e427c2f6cb534532cc92bd12359660d5e14fa1084c4f038571b57ac6732039969cd3493bc4e3b20180e9bf49f8e2b60340a63fcb814b48c9c43ad4e4b0cd15e3a6aa40a6a3ffbba2f2f743ba3feee63e4a38e4c668da8e488bcb8e61f7fe97327eb8978e2406dec3dc87bd320a7b3eb5eaa9e5b09756c1d6e673b9f1d3e54a80e16432f3bf45e15725947dce24a8a320a212bb673c61cbaa059547cc54eccacd233b9001cd23329e9cd80a8f59819e88c9e9ecadc2f274ab933a90fa98f095a280da796d0ca3137e6395de520917c194c6a46081fa3ec0d9df25a740a9f3d1369a0dd5572218e73d15f93f1a7a475bf6d22a69253ef8fff1122583f9751e040ff8e6833eee68c177b0d1f508957b4f90a49c3d9a7ec38ba7285267924d45eb4cad48e458696edefd67b366077f68dd2372c2f1eb69cfcbdefc9b5c907f63b54d25011d56eb208ad8efc8333ae5a6e74268df67437879c855d25c357e5d56d8eb69702f4f018fecb3754b6dc5a63eb317b2fedabe7c6a3e6f48ee8c96d6b57093789e287a5ac22e5d1beeb0bbc576992514def72f9f132f19b32f41d052ef716987039976f39cbb2ff27ec7cb76e3cbbaa148c31b9787a3b40a81028046224b07639c47ccdcd64300c535cd0961b45f5f723b07abed7e8066031359e8d2b925daa81257e38845cac130acb95ba6560b02294b7039ed6884f1d62420315cb78f7ce6d0d7e4b95bab17d4385079d7e5a9b84f3979494ca188ba15a4d81fa259a4b3200d00a5ca117ce36615e0212794f6951982f65a7cfec75962c1895e75eba0dfc82c92ad371c23f161ec64686c12c8c807251cc01b264d1044ddedad0112759e6deedfd50d232c0292918a3ba50cb48c827bba6cd64e4e945b1535b7c09baba43c637c9ce90db0370b13c4d867e94f10ceb50420286d12d7475b38621c2bf929c31d70c9c492c499644858844080ebebed91987d15b8877a18e40fea7f6af33757bfba75d294a93c1ed6eac215344b0b4002281eba87ca4beb2a5cb5bb241b5780faf9bfa0b019397823fc5f0ce402cb1abe94f805d4d072acf8c1f2625e14601a82c2afab746cfb54094a7b5ca95f2278c1069385b318615d35b52f5533d633cf5be2dae27c421f4c333a3401cda2507134605a8f2b788e50eb39c62e14d4462a841a0481dd82653f76665beb4f9c77ea55ae9262d33fb2a98413c2d40298e85e52be1b52c1027f2e385a96430a2d173ab4bece5bae6988b928c946638e6ab6c0f0154eb55e13f9349f3ef621009f7a25d78ccd8fced9db7bc4e63dcbbabf83d24441b89fbe8f6befae79b70b3d230218af630f7834873c367218e316912d71dbb9b593ed51559f8e300a78769ad324178e9ac61a9535288af616f35f9c46273505c376ff159989b42ade79543655e3e07b3dff84c5b0248a6813da5aa2645e5cf45d3e8658f5a564c77a3976236bf5cf40e1a4e51fec05bc62d8114bab00cbee2943bf4d6bf112f5ad40795e7e897d8e02f6473bebfea6ae9d81706731561df8a5af56ccecdc3a456f55e6654a4bc93a6ed014aac554c8ca0c05fc357ee86dc7541d7f8bd8f3e69d615fd78c9dd74d9438de3c87cea6b5429ee061b7a4cdeb7168cf6c0c93dfe50fb8278c6f75c1468ff8dc8b228028763a907b43afa0d212b4c4789541d0a44f76109a800305ca23eb777e8c25e4c06ad553d78313695cd2a74bd776ddd048f7f671e21ece03d84c787606a2d9c76516f8c3fcfbefd7cc096d39e303952eb8583b8656f58ac758c46d64dd694ba2570c0bad2d4ead4b8a41177ff636a59e0e176a64c3ee666b7052a4ece5f26343c54c5f87321c2066c12fec95d42faea17e4527f49572e6ea5980ce26552d4fd91daca0844bee954130f0ae7b47b5791f33e849578dd07f8e246173e8ef4c4f4f1b42b2cc99dd5403bde80c675a43118951553242d0e47f520503d46f0fd6128e8629c19ca9159a2afb078d974d8300ad923c1dd4d92ab00d9093f3ac10f30318e8ad2591a0b5b460de1503e1f98bad94cf8bc1b59d29d7407a5abb4b9ae74df8dc8810bef02b7ff8e2b6e3916461e7f72bc42fcda0a870a2e1a9868c6e17a048c3900e39d230120cab6c844efd37fb66122aca3e6b6ecc2c5bfbd465c0034b8ddeba0fdd3e71a62b044c9902d6c8ba0f2cc44ea1fe7bda9e0bcab9590abd95529772de87d786f957df033f272817395af78f2c68a11390794f4c5625bc3cb8b6ffc7f5cf67c459fac8f44723c9c950e7fa55246a982d6213daecfcaba79749c2f0a048cccc89b6636a5aa6e4d70948793ac969d2932b4de7481e666c0c58d93a54ba09b9c55b727e6699fd3580db4bb2995f10fd3110ed549b13f4eb7016798c1cf69ecf792e62a5e8c308927e728e33772f4522e2e44e9e96b30b31c98f36090ce881e1884da3b377397110ee4e5e0f73b6fa81a3879a5e857d39c6d02de1d5316f23fea1a7c4f6cd6ffe972c80cdd7d6c2a9f5dd5b3bad69e5502d1a13b958ba50e4eea097d0acd797005e40c4d561cc5b7b8c90fdb539311c84c1bd3c586ef8eda890354f1b9e687d0998899984291416d96d6275a5d8dbdb682ae8a20b09eafa056807d6641f48d6aa1e9520e071a8b155d29c4d6a2c83de9bd5e6743ac11be80b7d3767287ea3853d3151983421961757f0af93edaac895708794534db1b9cc9e679b1bda2da253e52a946f0b4f26f42e52853ea1ffcfadcbec47beed4f018c18047cbd9135a25b9a062f04739912ec9b73e4cc15a087c95e1b185f1bf1bf180a5cef6885be00a42f7fd3a127f51c215252794d69274a7ce0c3b9e3e9dfa5399333fb5417a1a6cae251942b3f656169218f44a63ef4244e8bfabadc72d39f8ac462af03fa2934edcc1aaf6a978a3b0726de42bdbb2355f2a8dc9d312d582c5897ab69ff6234e9f7aa306b611193b89bfb1eabee68ebd146fd00e1aa5dee4c79ae37121f12f9ce7946d1afb71859a9ee84c5d2a4b89224ba54ca58bfdc79f088df278555f1fe9f0cf77d942aaab91ea9ea6aa9e252e4e71b78d8080a8041ae4ee616c227aa15fc0bb59b5958674c4ecf84f7dd90b9562b16b063b1efe56405530ec9af660c3fd5a8d9eda2fc17f9187a6ffbdcb619ab8d20c3dcf7eba3cc3fd453441576ad63400abc35bdf1fc471e4e570d15bc81253120fb4ff5cf6eab59c9d6f39769ddd46d7062419141ead3a0fa6a6b24e23567718b5499d7a88b73c1a766044e5ecdee14cd8c7c741cd41768afcded4d73cc6b54d2bf881a173ce26a3cf4bb7fa6dd4338a07a164bef2722d75a2af7dc443ea635ebd64b5c4d90aa2661280c6409f9950d5963aa4d3d25dcb377b5d7f4522767e95d963a3ba10596ba132fafe217d4dabc686540b8890aef9bbfc9b753782f643893da4e9543c77bd4d07352d98be326997a2ccb58f999d380b9395d8a6dd4c725c2dc29667456b4340d4871594ddf20ec82150c0e590e4a8c87d995c7e2bb14d773941a458b673c869aef8ee6041452dae137ed4f9c99900a6324dd6d997abb328f952f53b7764b43aba46360e7eb3a29c71bc83e255a909e06af3b7b1c21cd621a0e560f4381bfdbe7b820f4b22e251b9336dd33a14975d32c79da8eead1f4cdee430dd4408a05eb72b17ab4a533da7305ea5a25372204073ce600e6d82d8fb8f72d874a177e0a327d25dd09c7e02367e559dde8fa0aadfb1ec42ddca284ee2ba096aa7cce5a0d6fba8be7a14190a9ffe25ed26dc1ded1728716ebf8c7eda820ed0f6de45925e7d31c425cb0b455893ac272e98f78fd193fa041a0a677769aec9e0d87b87163d266a56cb3f5eabde8b12c97dfa5338ebc41a8a0463da110959f1dfaa768f15800880c3c897348babc362f0664d8cc62a7fbdf3c0cc82cedd9dd8201a56deda98362f36ca1931da94c9e7ff5117af6cb02334226befdf304c0a9367d0dfdcf7d713dde7b80e37704d450754758b7a72a1bc9ef6ee5e85ef0fcc40d8abe3e1707d44fea88a36f74f9bba0998d2bd2148c3f727d8dc3c1a2decbbf586af82c8370e0ea1443d79d38c3c3b206bbfd9adad2ace75ca1730dadd46ec59c545bcaa30cd1837e9f0b4a40e0fb672d4bec1fcad64e606f5580210ef9877f3fb907524beeed1793feda9f7c0ca9cb1b4d9a44ac246331b408f8db8237d99b56ab5d64e92c6cb11541c44fcd40c43dbcdd1b563794920204cd652ffbcf12b83ead2fd451e3f75a1750d04b607aa313d46e3bf1d0c3b88ea2ddc933b32805631046a99619caa1c0884dd099e9e3d5a6e8b0f8e4db2f8faa4d949ed393974db56829205fee4b0f7f5e0606247ccc895d58927292f4ca1153f5d87117b8e384d9ace4f1eed6fa7e1df8f8ae315f336e2d0b45e1e98cb57144b7a774253e54a9294517c175c5b1f40f7d118ad9658384320397f6e1a52ffd7bd12a87bb7bf5dfec827e911cd395896170cdf245ce17e7ca4b56ae1ed852e7c23eed9657d3ed7827df91b9c0fa5e6e75f0e3387eaaf32a33019d0d5c4836f6739ff58124b3f3ac81eb16604c84c9b87922ff236d625172b35cc8f5e827497b8e3e36803b83a8b4e43fa4365a338ab92bf7a0e589663eeaf3bf0b55c449894642bbca9cbb50c0ea5f1ef01b48f8601e563cd36309558b1baefaaef309ac676117132d725a9822366e7b32058346127a8a306ad54656675be02029423d53ae16de0cf14b86f7f6506288739a6652765dcbdfd6ba90efaf94c44bd1a7bca0ef683ef81c42ab1ec54a87210413db0adb9c6df94ae478931aef897b5473cd2902f232bdad5347202f4180589c590c2e08dedb177f4786ae2aaa9d50e64dadbf02c240aba4904cf01ed6f18bf15fcab46b32ba64c031a7965c98bb9969479783bf9d18222cf7310e89db00216541145bcd0b42c8c085476a81fc9f3cd980adf25a66753c8f418aef2e54c25128e97eaeac17221655636e3fd7966d5393ec6f034c37dc31f7b80850b09651ba018ae0007d259b8f4a6d2a5c795697c82d45dfb206438d0a87254716b6aaf97490a1076ca65ff89937da1670a0c3815dce9d18a3a1581c49cec80cb2ee02266540f2b5f467d0424fb689c3e9bbaa7f5264fb395210bfe69d70868c8337891f060d5da2f0ef7e8bea0853b15c36301c5a6daeef508a7262aa4f966c550920d852bb072d8500e26a9c6f45f2132edc978613ae138fb43f679230375179d46a3a6414c122b67870f018df5d723cf50f4dacc7bc226c6c308135c5d5017670676a3fccbdaf00ba4124641c2cd740cba8b46cc949349dd1dd24d1e4d7a568f7100588c8570116ff80b260975cafb69013719d3f29a028ec442d2313b8bfdf003cd82747179a49a5bde27e4edd4c252fa00e14130e1a620e2b87cf94e04d4383dabcd2095136ce5d11981b85e3a75db118a3bc21939793e62b8482906cdce35167e001f2310f0222f3d2f5478513b579cd20f76d54001a70ba5e7d93eed103007bce987501116d71b995f2d3fa35a0fdc3c4ed7bfa37b7a0454f88e61edf26698f67420a01a237793d2b6fc2a313ea3eab97beac1f0d3b312dafcb0a1cf568c877481dac5dfe836621c0e488ac64ec6a8ec8892ab3d86d7ac338008b52e1a3ebffc5ac9a09eaeb9eee5b33f67c677f4b552f7848ee784f6d8156b8d3a0c43a5a96c819b2dbecc470111d4c92d46a6633302048de1ba8a382892ca7dc05dab66133b1d3ed48e0e548fd93eabf3d41039c42c57a3324d9e96dd165e39889c566c928da762eca7d11ae4dcfd7f15150f0a4498c1686b3ce47538e62df7b3c3117f31609111cae8684689a5a2b4ed0b73f21e31ff0fbb30218445ab31756c338b8d2c2086cf6becd44d49f46d06b6b1e0088c00bd330a3225307af2bc3e766fafd4e7b77aa45a29c23b0ed2fb50471d1c467e483e47403435267c3aba80fa03811a2d203aef18684eadd2dd80bbf6642518721bfee719f51ff15d4771175cda38e33b39da8760c30989482422704b38f1544a8144132acddf64661ac66cd2e37307f54557cff45da5e39bce0d88cc43ac4f8c79f4ba79e4e9e86d4e056d99b7019448dd5e334755828b41c0e944ca1cecae13531c12911acc58a24d60564ae4f7943c1701b4ceb1c042282e660b89d233b4f3418c15e1f23f2ef5d117620af3b22f71dc73d0f232c856a62f435fa530fe5c53f4acc463540ea8871f2aea13a6f0b6d583f6703b0771530f5ca2349a601edaba3967e5f3b6c8c4c38dbcaeebc06726c9eba23109079389dc43069df50661a364bd3817df3f4b6ecd7519f3d5f7f1164afa0e099b65565a4b762b9ced7378d02cdad5b6c60c6bdc4196f5efe1f6048127609545f49e3454b5d4e210d5f0750f8dc3074cd30f4fbd553a779a650129e8202d72a8bb8906748dd61664c5800e96b80519eb3447f13a725cc136fd860e0681f164f395bf3df0a225d7ab89bc2a9bcaa39c323f90761f592c0dfc59fa6cfd0f699cde4aeb5f73935ac6aed400c839df0e6e13bc0cc3b8fd8c546a6f865649d2850e38dda4df66115f6631f0d87769975e9b94fe99594055e1cf43db62bbcb425d02fae67fc9e9aa80175419c6a89f9a4b18f7a08966b12482ae133e70d2a41ed310913fa93db69de77e78cbbdf3b60b5e4f749c6b198c96beffabe22dfe86a35e4a040ec5674ee6c504f02d8ea8b09041f388ac113e11882fb6103ddb0230e16f6834d5f2063a79afe3d537c55b919565cbb90737c2883504c68afd86fa2b3d7c6e45b555d7ead5d7513547a21c4aa46860b5bd244d787497eacac41cf02a181019d6d7cef0f030ed22daa0c0eed3caa1d11b61463b61a8bbc8f616bffbaa2ad956e50635bbeff35f30a681da629ba60e6dbd52d214d2d0e39f41f16051c68965892d77f6fbfaa5fb1f0e61756bd7494a08f2f10788e5220446480cbdac9f83c93bd0aeb4b79955266e472be19bd62c52b36d8d0671030042c6f3cb48cd57d6aed8a340b7de473cc657e7ce48debf3e7fcc4bbcb8fdd1b79bf89acae92b1a4300d2f56453d5ad28c86616221dd27f4674b97f964b479d71dcff60e05bb48c04b4f8ea70b049673131397bea305de3f658078cfd54bfb5ff77ec9a2ab6ad83758f4647e1a7546e54d080e129e3b697cd22391d99ea55ee25a83b3ec3c5e92f9286a6607cc25ca41588a612c75af04298a9bc86ebc3b5b14e779bebd63f8613db72c5c83915e1f855d3d1063ae1f7b1df5169263e243c7e9129745c47b4fcdad1e35e38563df49497fe83e8ffd3bd83b91379f39657fc044e16336f3cb5fcfadaa31578345265d5f7b1bce0f0efe358643d026bdc02f700d8ca5d61410a156c233acf18ea7cac717fba6f90022f858840ec78b26a0c7041a7f6c8bdd038c8f3f424fb3eab4934bf74d07303f2d3507d9012cd39feb632ff3fcd6f9ba59c31f6af830cc08a0d6343b1f1767df7d698dbc3a068ea3396f35ea5839ec75fb5c5286dc46463959ddbda603079d956d6d3f25ffdb01eff40363223570430e19edc981936851fdf602390738015f473092ccf70328c9a8fd705ab53ecd2b566de9aecfb95e2acdcd0346f04e4ebde166d55451e5cf5011c8bd0d7cac361012b997e59b148379dff18851f0d63787e9ac5674b3cd2c58dcac0cf7947c0af90a08d1a009b2b1798e0372eecab2af8d9ad3b94c4fb8353ccf328a35c5e10d12d5cd77ad5dd51e18ea2c5d80b2becde1970affba97944e6110a9e8706e9c9a4c63c38197c31d2c90b6fe1d4f022dd511821ea3bd70948777184865ad98afe261186bf040f10a41e08537b9a7e03e2c75145d41571dfc35debcb674569e1e09e71d04966240ea67adf9996268c4b0d8c0605dfe9a80bd2c2a4b149cd87f9d78760444734a00caece98247468ca7e97ec892445eb40d50c9ca822438d5f9ae098c9b8c588070c951ec6724291a5c3ff3fbc3be29c19390251739bf218736c3dc4fabb562b191e9847fe5fc06b39d03685e86feddcd75fe1d387524a2283b4408bc34da8629a4fe50846c0ecaaf53e10d210513356144f9ee91a3474dbcda9e06a9e63ae0fd1e254de426ce3468850ed42729928564277ad7c2e82d9ed7c1604b76bdcaf473c6e1019107c0c48e8d29a6631b735abd85705e29e91842b6121011e48f1450d913f34df189db63388c06a78f2de042e7eb200124b9f4396223f2244da8eb808d5a3a8e6564a34b8a250f43fb37c294fdf6afed349e3ad1817702bbabac6deb16ae4fb426eb444babd192d48e6558f2231b6329359ffaea839786825fad83dc7a586b849f02fe195622c359c9d03da5e2ed8d6060e0e399eec36312424f00d94cf91c6dbdcdcba7a3fab84863765cbc90df1b481a209ec90456f44cbc091a5ba52ef528d1edb9add5b3e0e235762330353e3d5ab99b66e95c28db29b26e7b1bf314c4fe371c8c2578e549c51a4b36d4b5fe2197186eeee5fdbc8047a852d9b57318ba0af2cbaa22939dbcd255f6df5bbd1dbf735eba0d7c310aa128e04b0a946a36c353811f5acd3d2dee3341d6c3cc0b011560a0cdc1e52fd22f0dd258e542e4e4275ab70b11510ed4b58c8fa98766cdf89bca975f90184a12c3df2e2638648da1c40b0f1df476286a3e7edd536aa295085249a0095712e05ec1ce778f5c4a8f4d94288755ca14dbab17027b165795685a52b04a67055e7de50b1702c41e46440ee2b41f825f34a04e15b62df3f7468082f6635939d939f283743157641c3399e4dca1f7419bc3276e24727ed11d50101336a1623f110e7dd38f7e77d5be5ba425683ed80be11ac8c56854172156010ebf2b0e778bbe3a89a427f93f86dbeba43e1c50b113dc678614a6af5057e003b1b0bd18af1be7a6af963d7f9dae4592147be826bfa5c63e379be6f2373b45825497079511ecabf88de5e764717fb0b913680eba21685567bc4cd17b9445a776d6884d406d622427bd334dda38981d8e42d92f5203c855cce9e2545d86de203bee18ddb986f1604a7f2e68e3b6c7ec9d6ab6ac6d250cb6051f17837988514d60103cbe60257c43e663520927f531ad0252e0c62a2dbb37f5c66a91a103759f90fb95b8aca618047b283839bf2c4ea1d8dc9ad2b014fbb31761a349467db56662404ea7aed0de65867b78de413f0a04d892c3305c66fd14b738e5ee7dd4f24f9e4ad248612a453598acd6502e8d1620a67968ce1afab33aae545f62735762b9ab25a0d6e84d43f8a0f18a66bcaf7a21a7d35719911042f27519cd35c8ab8514281852681ea6f2ec53a4f934b92dc50aa68d6070e3818845de6f4ecf98c1aba4415811e86f00598fdf5d1ceb45e620c1a49d4246702c634a65351c77b1e84a8cbed6c48e97d3676d3e135f298b5298f26f6a8548912a60bb4fad52c01f66451d015aeb01a32b12651c04a74b2dc850f50d5f84f81c869fdfe70b64ff6e04fef5bdc70098f4fb6ac0c3c755b5b8390b3f087b570726611996b4db89d68fc9287e96b72d91bbfc74faa717b114a254baa54154dd22b6bae1d79e1ea4b48952aac625011aff0dbaa5e04fd6eb2454da6545c23d2ddb0d1b9aeb787266246e3fcd733cd59f1add6cd8782a62c715d3301f4fe44c4a224fe359a1cb4ff84395a5dc04be7ec758fa4c5b10c4a1d56df370f0807572e81c88645b3e183d70ec0f0210262634dc6c10c3d64d1bbac73baa17e57fafcc4e8f6704ef68de09489626ea4db079c3da23a233523e82c78d79b5a17a5da318ded36516722684b1a472f61a87c8c4fb0386b1231638a466e8d9e057abe79d2dbea05ef782146dbcbe9380741cf6695110b69f1b622eb9675d753e0784cc2f1c7b93d0687cf903f54ca4ec58b9d7ea9eb64e840d5b9c2857ce737ac487e85222f157a92508c8b00d218e9d6b57a92176a8b33873dcc13a397fd5e8a538551e6221fdb6da817598326f470c3dc2f607443ec45d1647883ba663e5f84a31beb997a8bdd86eb2791d50ab679adb5b0ee362439edb806b2b2f95b4c50980385b245eb14ca11563af4e768bb3aae0730a265a9c24b667e0c2d4ce629fa491c38f1cc4e646e129a93ca9ee6399f98e44ef538f41477c1de247f8416c332cb63442538b8aae48ae6c9d12f2bb8b54ece7d3da4aaad25317252655bbb182accced0f05038e7d65c1082c171d9bb81d861e26219e1ba0e5e5f7217a6ba451e0e5280c5833d344e234b4061cf4f5f1d769188406ad9e9384a1479be197ec2f0fc990565ecb991d32895f4f1c90c425c88f0cb5ca44d44054aafca0c58645b43e0f196219520e68510880f02950ed28307892b25a9e7b7a000efcb12523cf555b8c06cf7ebc113bf541da2071b966592c7ccc55264228154b76387d39f388a0afa16131eedb09a809d1406af07202df6d0a6a8af427de4dde87980395483707d239caaad51b51a5f24c972d2364c73b3391a659d5132c228b4e007ccf04c5bae1b9de0060c8a6e0ba55ec9df33066f100d32227597787ddcba0bb694a997c0cd59a60f1383ee7d7ba428c325915ca9518a81b74e818a7b975f539e41031bfa8fbfef8af765ff2137038288ac28cadf48e12b1a161da5b23d993ae35916205630c8b1ea1c839a9561f6e398984921651f33db36fbc5376f408ad0259abcdcb6b447aeda4047f11238e91395d36df6c7fb337c9cb52206b6d849b8a2c522dc710042d6a701ed87b3c27de15e0cc41ace739f829b34109ead905a056ad5f398df98de005d0766ddcadbfc2c52fb1c0f13fb500876fb48240448951300679ced22621526d93cd1097527bb76ccef619c7d88cef5a91ee66eb8aa820a7db15d11d12586e2767015170bccb5645abd6b23d4d21247d183cfa6fd6e78fe5e5b02a65a531c6476de4c3e1e778100aeb2d88fd1fea3a994bb5b86fbcd2ee53d614165f4758b13a8691fdf60ac9946817b0852c877f7bb89387f1362966fe8eb365dd0fd8b30172c29ffcbaa9e9d8b63c6a6f6498dd0f736ec8f5b6c1a35032766285fa98c99d29b85033077c118bebd178141c284e204faa46dd9a01cd8e35134233d62b1a88083f4d26c5328f253adbd3bb4601f0ea1f8d491ce1127c5610054e5f51d79d0c0e5f92ea9f97423fe9bc3700ff50c36a84d3245e25e469bb8fbbcff26f50527e7d94e57f7205186f33d1b40f9e96944dd64e2aaa185959fa9e4c66a91bf7989e86d7e1fda2b560f1b3e8197082832750926b9d0f254580e051fc6d9ce87f52519f5963c2d5c5548fdc262593c090556239feb096ca9c613d62095cdeebe3942633b0fd3520a91fcd442d450f61d562aefaf57e0a2cec0346413fc15a3e8a319ec0cab4fd2f31d446cc7ddd07073d94292fffb527bcaafdba394195edd5b400b5e815a1b5b8e06041e852a00a4a92da087c67f3f15cb279b32ae71ff3ceab740714024c6fcb885541234c1e7a9157e36114c7c1f7d903b974427df3ab82156b6a4a3c936cbdeb506bb87ffb02c2a0815047fd10d219e2691adb215f7eccdba95248c1314199773d9b1ef2bb76140a487577e51c060ab7cea53dff00a3191ce0608800a61d3b016ab4489bd33f243858dfd893f3d4a27b61fecf254e0d486ab0c2ba6ba87eb984949bedffbb15289247f3a13299f4b163618bfb168214a11599162161c107f9ab290b4b205b8a1b7f48b7e452b98b1d5172b8dae7afcfeb87bc1221554cbda7ec6cd768093eb8c7ed86e56b87c0b6cc1a93e067f1ab4352c3317b9ff39e525b3e6490a90370a96089d97cedc2225f1d9da6e9ae90064b781cdb687d76a06df1525c06846014682844ed29897130a134125c93146a44ba6dfa401c6ed8d2aa7801b33d815553cb33eaa396dca3a6f6530b999a7119b5aa5559946051430418f625542c971dc2f3518f85b8b886eb94dfcbf0932d9513a2d4a9f715f47ca9009a873be9cfa1a70ebe5f22c86552ce259a5a13199a99cc402857ef1a245bfda754f8269bb1bcd2221f1bcbe4ae14540aabf3fa916355d03a93681e5ed2f65300a80bc1832ec043d54389e84af284a7f17b0e46db25827eadec1a99b0a15f5f7f83ae6ad38796e3078cdaf4a9e4f07594cffb0c2b58e6fda629e204cb8201d5ab77e250ff21d8016dae7608359861e2cf3c832f30912f9dc5e2b30ed689e024f4d6990f5a47b5f4def5998cc86a2476f6b614312d4a4295f2678aacf6eaab7bf11453e1669d1857d6a22b50c2cf6c53c9ef1803c6f12fafcbf3151b7a89bc0c7962deb1f151d2b6b4d7e074e0cbca4eca4096d1cd99d3c1dc5583194be5c02866d2b38a1d42ef134f2756e03b12dd2e09859e748b5284962918df80be188e1fd68955e62fbfd410af3460dff9f9cba01c7e5f687800c41114f750e3ab213f88d9828bf0157366a2c91f7206df698df3cee65e18448a2adebe88431292d0bbf7634e51f4f88e5548c2d5804af10ca2db404ea3517881af221d318ea4a5d35c818479d84816784a142485769f34ff6d64c4ee97801fc4be91e47ff22da46d98b6c8e9b072a29ed40836077b4170991444447491aea48dd4939eebea09eba2e287437804bf848ab9816aa051d32771c9aadcdb5f05cf4c0b00ea1790879d14cd78e0846b9bba05c867438e92911a5391d0272f0890f4bdb6305db24b0b15ef9d63da05e11e4b6945daf02e7ed4805b89a4dd4976e4318b192fb292c329e6c4a34151305bd46788d8111df38b536195533221697ed51fbe05444425bd2cd108305e3ce948b3bc3206a634c2ed260e7b333b5a6ab7527b2ae556b515b0ab01817510fe9cc30d571fe3dd68bd53f3f9419ae9734a65282c45cd0b0e4a37a235cbb80a5697e89b958f5f9306b078a2888219bb2cecdf719f6c04ba27a7defde4e80aa2159e8ff8da70397c9b30d0bedf4ebe5fa45819dbd02d6b0cda9f47c75aa165bfe932ea2776d2348923ea238b8487724b02b7d39b122602f3224c65b816d21edefc9d03639d760d2c66308797d986bb3e04b198bd04b01400f8d22dc2efdd4d75c3bb016f34cc814d96d736e3f8eeab40ed37eff21a88efff0940c7d9b6557bb0a4c12085774672bbee73e9dbb521ef068e30b628a5fe053895513daab0c1683ac5073d940b7f07f4cc42dba2cade187978d534f7d077935394391d659a44aeccfe8c1cb3d83e945565909e21867aa0a9bd144890ceb514982993e6f6177e4285b79a913027e8d3986c2f7fb263f30f4ca1585f1ae5f9ddd92d13bcb908d51c862b36c84fd4186c99df9bec782af9b488bb478b945280afffb9946d711119cdd04998ea5bd41ef76b1b3762cbac9706c78cb8a2a92635cf2d14174333240b88cb02975bc6bde041fd9f1f22f531ff8d12ff6a6f8b0faeee4cefa52fc02d735c448896df3fd243d13d20206e4d3a394cc9e35d1351b9986d29e413d95031190fb2e015ba750e781981133b8e275ac41a6d9cc9bec78f8b4a7ab16e8c94de4ece08b6f3c5c2cbf6441ce471f0979fee78c817333d8571b9f41c6293ed85b6e78ab30df7c1ef3a4c71424df26e264207837edea1a6f5ee1d103860ac531572b40d57f494f2b255b7baca346feb2b4666f78592e473ad4a157f9ee535d6f778139deec5a2cecd0bba6f3bceba54867bf4d878571b290760f1528e3cc93d75c8b6bec25a594cd4807aeb301007559fb9cc40109b39770a8751d888f16dcba6ea597cae000f359394b0b9cbe77944d68cb7dc8434bb553e0ba3e800f444fcf9bb37ff6a1adf730d4426c9a810017bd0887cc533bff8496ffb3447410ea44dcc1e3e293c50c840e9082a1b533d3ca766494171358c4a8bf612e80476bdcbdfb73898440ad405e10c175f249bacc1aecd6e76c874136aa19be7d88314d4e2d0368747f25a38ae199fd649372768547c7efe8d4bf62f880a00b572fa433694f0e4ae8e02e89e474b993dff21535901e56a7ae59c8b46d4fd59400d155071a9a14c93e0f8bac35e41b3601fbfdb3e22e4b8f9c4b4ddc883fecbcd9e47c28125f27a30ebefb1a1697a990420a06db6b9173621ecc0dc59d2cacf1ae0deff3b17c24873a89985b83d02f06552b3aaddd11d87ec58560c63fae535c3c133f3f0ebf85fd4d043e40fc4a9ee8972d14c1335de16f196967a1e94dac975e5299aebe242f40a5be4c55d1e586988637a381b24b15d65ba08873c6b592cf02d52b83b6b3cc0c0c5b99adf3396cdaf5d69a7ff8549fb28254310092f314a6d203e8ab37c009fb3d00bce4076e2773164034f62437be8b363c067ed9acf83f7741e2447216f28a8ecbbe449cd12e37b1df8d31f6cb47f5b7073c58c218a801ffd295faf54aac79875e05894b66ab34fd0c8f4ba6a112a0b9642c86c9e91a146692cea834ad7c19e49e044c821d7eceea32a4e27e02a74320dfd9000d04295ba3c227ad96804a0dfe00dfd6c0e6de0892d382db5471ce9b8284e0604a84b7d0552ac3a3d8d558e6f28f8d73d89b267d101a24760ac23d2c00c7f3135339da665ff629d74aa824447f90b70eda661ae7aee0713b380d00e404f603e5136c148017a398bdcfbfd17e01d1213bddd67f22b22f69e0fa349f83ac59da5c4d03431d17d6153f0c59d8b407100eca1c7b1cea646cb5c1f37cad27b83a851f87ed3b6d62422e7e91fd867fa10b7d434b4ba66c122fa175c608e94f452600c78eb370d1e2dd1bb23624ecf74aa2687b064bce04674866e918ee75438869aa222c83322a786ffae80256c7632395408355fefc744363742f94ef44ba881ce83b7399343943c1b878ca5792c887b07dd040ccb5b8d64258286a074f6728606120224fe992fba0d4ca2c129fdd3fb351565cb6e85e4671a1d148ae377143160408ef911826840ecb039dee66cd26fb0c09d7ded79d1450809d9bb2c51b8beaa16fa06550ecd9842cfe00ed4ce7b58aae793ec901472c43bbe631e70537dca1f7c594d1a4189264b70017a36580713a4d09995e71c59e61095b735c1487555df5cc1119fdc176dac2931612e0af086be94bba844f7a98859387514f438b09656902ba6f5eca44ca918e00d337b26cf069699d99395013bfd5155658cb9c5a4ea15b1509ee8e21e0ab314d2e7602b8f84f5897e0b47878a5721eb11c7b48dc1850b4267d46d19f423a77e323b84493112687014342aff44c480bc28d44d1226e070e10891c0d06c0d9a8e36e0518414e49595651b0ca3f6e1fa6d9ecbbcb3b85f72e8bde8d4fb3fd6274019ee147d5928bfaf5e7e7cebfdf2f9cefb8431f22ec9ab44695a818d6cd3ed92f6acf2afbcbb6c5427945cbc4d5946a380907bd353d2e26a9665ab521019a41ffad73a848f9ca56025ad514245fac007a418d2180afc9ffa01c2f2ecc35d732cb8df4faf1f23139b129377843f4e5b541a70a137c2c881a4eaf166346f71de0ae2e0413060055275e92037f49bcaaf411cffd74fb4b78fe76aeb580c114a8f71c4657d728a1b79b76041a2106b9289bb82185f7cf603b68231595d7d5dd2b49a55a6e415b077b6a1ab4c38c663f746fb72b0a6b5063d0560646ea28d030f7febca3324f363e3b54b71d333de5eab5b3d6a562e005e08d9b8d935203626630e227d87f53f8a09b0d7795add3f547b51b4c7a762bda56e685e436f68c1a0eca2f275607178f333159078bbc6b451ba7d74675b39d63d12be98a18d45c056d877c8d42a8bbb7021484f70a7fd0ed73809f883abb2686cc5193599511abd69c0aa09a1ab322a9725eef19bd318c3f27d39b39e9bbb7a87bb8737a8eb83ba8a733b43aec1daac3324cb9bd5bdd86f5468fea7b5ba65a86dacd126337218dbd97961894201eec6f97fc1b80454f489ad313c7a84c2ee857644965b5721e8fb26459af1037a2b892fff5b4b5f8fc5bf7ced03e41d68fa158650d46314b0a6c488b25023eaeb4e6d118005c1f8b86fe3b0d3792ada065b54557b496101d239277de697a094dee070774fd25ccc6b75f88cdab27c92c89eeefae1a58393e2c4f593d705e058ff86c846edecf519a02a7da8882e1e0c0bedba44811a29430625766652a36a924e3b9cc25db3f988ca58477260f4603d7ce76b56cb8b8985a9258f9c3d7954caf237215b1610d4194563c237c6eadbbf173b6f46b5693a202f6dafc4cd1c2e24e8de7d0fd0c864ef9fc7d9343abb084d8d821d822325a7fedcc6d43651bbbb73daa7eacc8f28d702db1612393a7932dd72739f07c69788eab39fbf266943844c64c002a8171b79dec7a97df95da7ddfa7b3707f39feae943204adb32008e2eb00f2fc356d1e24ca126a61d01289a34bffb4e88cfd393228e3bf65a89e7751fbace80256ccd2a8179a2b356698ae60795a697c72c5103f7c468529d813af3c01caafc044e0da5cea30d60b90d62a44c8aba072c1ad40d0f94b1c6f66075a7e8ee8afe9fe4b992a8dce572bd83806927ac7f210df4fdc2ba5bfc570e98891d696f48493fbe5717305d6bb4f7e9c53c2ae2edc0b5fecafca226ef9775cebe9cc8e204b4b24239dafb6a58c66cce6aeedb458b3f274845ec7be40cf7efddf85db6672000dc99fd5f57f8b72027828394b6d1444290e370e756c80d77ca1c862b363765e67eaca8ef932bf8ba7098dbab6e6bc99b1dbc9a35735a843905d1652f2a3389bff73ca16d2963f2b79f133fe693496758e64e6ae9abbf19a4a542a9493441f7ff5989acc24b9fbec1ae2b538ff24279fe3c41a6f85dd560e239fcee423873a9eb258028df164c8853939a1148a987cbcbb2435cfe0f9734d6e1c6451b8c136aa57f48a4f4055de3157aa4416b3539919ea6e84e1c771161873efc0f9183d7867c54d9e096f5ae1602233ee4be4849c13754e6122e392b9614faa1001a1c46b89865aab25d104ddb797b06283da1380cdde7271325e3ef6113b51d6db81489af22972ac8c423c17d61a709178ada438d0b4944fbeb135a6f993fb0920121426e4a63816cf3cd81434dcf3ff7f370d86dd8c2e70dc4760a33424991170c9ec27f20383122e63bf1f12e990ea5abad52e3d47e716038705f8e592f8eaf1bb36dcf0454f8f884cc36d5fc8fe0154c595e4e84fc3eb34e1047df224cb7114bd4ce684640410757e2467b870449affd1a8188a543ee99a55af1413efd07af91c38a4d3217a39e78b9e40dfd1bba0d324b0489498a0c72ad3f3cdec30ef8f522382183d99dc8802704b04c781d51074acd42207979fb7b1a78926ce2302670ae757aa8ccb5de4062e765b53487ac0b75fd91476b9b2022f53f356fafe3a55d45f7290c11105db2d88c2a33e598ccbe2121d129166bd0cf268153b340921ca00e5ba04d288bb889efcfc6fe1d06f50db11871e3ed895488346eb2db4d90465e68edf3c832a7a0327ae43b2ad89d35499865e59d48926c0c2aaf04ab5de1fb03a879df78a5017128bfe9776edb1e21a9fc1155512bb84eba7baeec5712da1019846c90e1fab1957532d1162f665a54aa41aa5e616fde1e7b2cc0097ee537b5555796b0060b6dcfcc90cf7a198f485b5a03a3f948446c18d17a1cf90dcc26190be0e2dffc49878729234a3517d4e5cefa454b921654c1d4c86438d8c71ec82d86b918c6e98e5077558c55edd7e602f3fe1891009f93a2b5f306dd1d8c12faf92f49c4a47e1bc6a6c974887a016a016f3728e954844bd61b7276e0cf6f6c4517ef8ae198bb7e2a7838dbdda826ffecfba30a3c0ef5874ab914961190810941fd4d8875037756b390b44fbe705f92283629a1b54580ef7be53f928551df49e13f534a6da67effb43c8af1f9d429618f92d3c4b8020146a9abe93fcd333920e2b7db1a81c5557c4f62c4633d2ed3b8c68aaa2b659dc9f91c5775a940bc0dcc9fe66ebd1ebd44aa676ec19be2092b32e705a1662d41b892061490d106e8667b1486dd89d40e08c9f23d6d309c8912a24fb2cf537f19e830d224eb47681211b872ee7ade1371049cba138080987a0d1abcbea2bf03ab419a0d3802a3333e5a5125ad1700e458ee07514da33a70a35d464326eb3b73fb5ab0ad3f05d23fa2543d8190da84090affa936d0f8b059e0ff6e63eeac96fd872fa1b615e8e582b5114d8b31a83255f51e54c624fbad1fb358e7c465393855aeb6a1b2d4820b87384d8240127269160f41fa3df80e41adf22f871a55e17680284274b3dbb3ac76b670fec7f5153ffdd13a43b6a87f1f66b8649447b342b6ad4c9cddba03bcc23d68159615b1748170849851d8c156f19577b3029fbf4b2bb62bbcbd5e157b0273a4f0cf6d10ab2a481c2aa9ed9f24065ed97bd1941d7111b53b088c87fd58d4d40c81d997654766b9100f686619492b07501c5086adbde4a801927f9d94e539706276b3bfb4b703e5a1d3a835bd55e48ab984b82ba28bbd57683ac3095543788afbffe02e00cdd6b893617bc8350f22ad11ef14ddddcc62db6bacebb6c3a242d6d32e555d03b990cbbdc812491b169d14dfe7e87d28ffb3e7d8eead30b834abc0ec452ecb58350ff10f1f7b15eed12e5a8cf9ff115210e00efd58293b5ba5a76c0fea2b4b15f401797fb502ade43feb1959bb0d870d77d177d17f545ad20eaa095ef824e1726171d4ffea77f1f1083c845eb4119b153fbcadab5bd87d46a5d049249e3442bfa1a9f4b53655ec936f6e0656e8bbd044e59a8dfa8f6cc6939897e977ad6a6816cc5ea9d234126a868b8f46526e946341412d09645abcf340fe84d19953b458940562ebcdb8580d68e4cf475ece10a0a705ea43b9f8af513c658175038c5cb9406adce3628d84cc4bd2696f3c5f63836379aa23aa058898b9cd16b1ccffaa066ac56746c98d4366b1110d1d1571e4d5cf53c6d8841de536836ba7a4ac8691775c8032dd7360e2a92365210c83983b7a431fb55d1922a358c127bdefda0cdc22b05d26e3f8f351d84ab67cd155c57ba02887ea5cd7bf914cf3f8a1f5109a88d907dfd4297f33c1683cab4521269670602400a841286fd6860c3c837357e355a5321ba0a0ba6a69079ad9782bb69c593a4517bde5d2e489db86b68297dac1d9f6497666bc2435af8c232c76c739b7bbb84e5c0129fdcb40dc7f4f6374568c112858c8ce30fe5edf6b5ec728e025505832c8d38389b370fe1cde9804cb9e61d75083ca36ab71906f393109e9a2b914c0cc3a27843dddf8c572011fcc0753d767d28db532c90b3c47e7e610c4e599d12fc74a7fa92eee257c2c29cd2ed0f0127fe74f25b2eb6a840aa25098c1ea02064fbba5e4e0c35b65455b9bacef3ea3f6966744f8553e0025f09820648b6856d74b6e4b8b19100404432a5898957bf7874e48b21462877d67d3bd7091439052fb9ec62dbbeca5b7209d9f99f0467f735e7d133ef66bbb8345466621481157687bd2a8fa0fda5cc90f6603b06ea9de23334aa2f89f88488cf6ca26b88f084db0187ba2e01e7c98252ba6a35178e09e082f6949cd3e45d151b8aabe34ff23880fa4c89ccf5ed21427bbfed80418fa76e09bf9f9618090ee7df6e8e166ff6c2ab220c27b4a28d24d78192abc208ee415e48f013ced615cbb5286e42ba30363384cd95265de29608873b8c83cd36a995c5aec255baa7a4d6c808a8af41e15340b20185d6b83a6f3da3f3785b67880f60de2e208157d7cff524d4b26a77a8dbd05ef4ecd383b57965cb82477396b903d51a52516e2934883b05747f2276904cf5c8eacfcc3304122441f68bb9c1c3bbd49c5ca04c695e69b6a53fe752a21c2c110aae55ba70d2178aea80df75c3c3ec43b21effd9b421c1d9810b44e4a9badd8b3b35f3e1ec343692f59c81fd8d048fcf5b79a4e274dda8b16960a3841912ca02c416f7fca10d292fc3312f87cea33a71a712dfc019d77383fd5db559ac7066276b064126ed2df6b6c690b7454b977e901a5cf91366f92e4957b35fb1406514ec635c5d2bb27e8ad5a0dcdd45d11924c3935e116ac164891c30bc14c1f76dc4a769e5d4e083afc9ae90bb99d639c58d2b2af481d7f54fecb43fd1806331761b60ea7adefc948c4654b9e02beaab1e5970f705f189875ded7ccb027e323f567611a5f14c720f869984bd247894883025170cda475edb934816680bbcab7b4c0146b3c0a8ced319350691e0f4298ba223c85d31bcfe40a9e88b9de459f63b28d46838d97fa895937393b0af6c2cb130e1fbbe12bd6f35190bc61b82553a21b28f04e1859b74f769d77e62736d4bbbbb63866fb0b6284f83ca3b32508bd737aca82c07a433bc0acbcdbc7fa701de8b9bc26d908c8267a1c54451d3c90a8e1492576ac4c1f489d2e9e404cd64236288616441abf828da0fcdb0503319c054c736b20841187c97f0a9f911053b5c303410d9ec24a9ede578ce2052b9973241aae73435747c724dd4f32df35337cccc05128520ac91a368985fe56f0de53c56950663f16fc3a72c39226fc4ba626432079c80ccbabcc6ec03c7eb8bd6ff58acce3ca249560fb4c13218b2a8efdce6233343b1219017226e8b3f52b7eba10b98a9a3cec49179882c19665337e94d49ad8605c64c90b4b2bd09a0dd29ef2a35ea2ecbbc732c1a8a7605e18409a9fe27caf3c313d91151f3710ebccd8de1ed8f0208a3362eb899db81f22aa3e4dbb0d231404dfc9fce401538ef349a0f5e9553f53e74ecbf0e1e44d7e144ec938856b8d07a316adac62a959f22d10a5c9ba1b11eee6d356f2e189de53ea2dc29ae5bf87e255e1fc67261bf1c9633c04524e4c03057874c3ae5aaf2c8fcbce8cabb8fe7fc2a29459e215cdcc219db7ab122b1cc3b9a6e1e6bc61780667a4684a70062666a72edbf4793c74c76fd6b293019d1da596ccece02aace7acb3be147028925ace8798779a0be7943d5a6033b758bf18dfc210dbd7641d7419b030d5a1743f7632886b3ef3a9174cdf2f2aa15e535d77219fcfd8eba126ef6c9d193c12b8845724ccd1da1df9e6b8109c7ff7d840021a13f1c8e22a838e8bd8fb75b1648c5edd69f23c378d2664f0c33e56557029308f6aaa53aff61848790a0a37ce2641b7ec1af6a527adb56d02e6d6aa1e8ebb1c2740dfb91f778f016b723718834a91282cbf4ac9583d329581a2b4965be38c5b19af06b7f84a8396b8b8c7a2d8d1b0659cb6bd73d73e48ab9798d7a71d5b1e6de44868dbbd964e280e379cd5f9266b3fed965d9485f9f5071641f228bc62f78611cbdba59baa46eb1ab3df1931f61e4a503c73d5e56d4b12bac94ed43d45358ed1ffa4850aaf88c8e28f6aeec36a8727871f16be5b54f4668993577d61387569a12ec6de9f104f8205ff90ee2974d09dffff0ac905464708b7e9c029736362c0d99c511d8fe322c8964123dc8ae16d872cfd8522def2d0f4b3d086f5fb747e2acf8d202381745978ed1a21b5753f9a105d5a0a03d94efd5a02059264c4a2e5bb9b184a75fd3635d5f0bd5e89983033dee7befc1b8768a0d2b47b7330fba904ccdf17d04b92b1858463905ae40724e519b964e9d6738a0a99d7b9833b0fae7472318a57254fb16ef02bccdf0516c5824e8de4b185bd7208e3e696b278078b1382dff1b6ac5a10e49a03912cfd2ff69a0269031d0775a44091b8986c997431ddb1a57b142ff58125fac55e522ea64685e7b8b0ad81c4af56a01ff6b87eb5e3850ccbc8460148399d014cdd31456dd933fed3ec9adf95cbaa4b395783fb7d3a9b258376585d266438b49075c582100aa65aa87f4f734435892c4f88e82caa3327a83e11adaa801124df29249747ef370167b3256c7aa873e4b05f6f1ce43a352e1df4cb602fdb173748b1f97ae0835e56e42bbc7316645c8f32c9e9827953e0ae80e6cf5bde647b09f2e5010e663de5f7ad7270d93fe09c721a8d721d2d925ab16ac29ad3c555998eeba26bbf9cc7dbb0d982b7a0ea7edaaf72bb99ca1cb506975a703d984417690606625d4bc937363523644cde934bf9d1ea15751e9cc5aa62db5e5851ff66e2470ed7251865f6bba8efc49ec95bb8266bd405578bb840ba0a7f300aa0a376b053389df01a6aead95a4645562845fabb53b176be90b6a687325b14abca40f72e1491b555c084e65fd9622b277fb1313de801138b146f3032763e6fe3be121e4637c3c30e81f7fa337b61bab43dc3c20df989c2aa28871fb4bd48ac3e0fcc384f48a70283f61ce865cbb3f6236c4b8c6d957884a62a21e28f14f09a6fca402705bd71bb0bb989a13de78d8fb75284513f211aabef67e71fe95597d053e08702650ced59a4ebc41f4bea92d4e1c6f3c85f2f42edf8a02a78a534610ed362c1ba458c3ec0b1366229c078b225507664a3e4c8ca7c5671c8aab3b656a5334cb0a67747677ee12f9d64fe6c334df2370ebdd23b55b7af3dbc0e82672eb2e7cdd2e455aad8c86fec35a435a5e6d0c4c66cd5a24f86168374d3886f096b5499fab27133ad910d12354f8f151ef67dc362ff9cba21833f9ead1b30a861bb8754289bcf47168128895929c4a646bcc6d430fe6f53d47f5fe421e284ca81b375e4847502bb849bb585f5ba1275cdbee7112e2bc29879f7d26671b2dfd15db87534ece817fe9e840331b92007ada3d7720797c5a5c12af486b1a6159efab6fb778bfdef390965bc92edd06905194735da5ec6a116dce82a00e422ce0e9c9d6fa2c0d435e279fde782b4deb9b548467353b5dfa9151c0445995767292bd1702e4f030d74300601267cefbd0e63437655ec48a47bbddb00f7b25aaabf6d37489511ef88c1ed578a9c0a3cff262cdf37d14990b22540a845b8240b63882c1aaaaad83c757f4204ab85593931c217a637db1e19f535d8fca0674fd22f99b3e53b4426e5ad4f4767ff760b8a588db3707b04bec251bcf39599a2d1bbcb8e36a201d5b0accc0758b04e2f55dad7d4ef75ec7f3e86b06faf0f371f0a4642a4ff201c7843c9ff32561d763a71aac7e662c01bf507745ec4e4437506814b0875e77c7b2602f3e12d188ad1062f24386600ebb2125188897d4ee686cc5553ba48f253f5e41ed35ca2d00fd6e6b833e0f119e3795764eaa5020f2c89af107fcf398a32375a6275c79f1586e5480f647c1ff214430d6f83c1db8299787227a451dacbb2061ead4d65d0fc638344b2c3425822aaf22abd8198a9d58d6d8dbbf27d681a1b8f157497bfdcfe12471f698c928b0bf183630f00d23ba5ab68232a5119fa1ea9d7dbbedaec55af065df6ab322e1e885842cc1f718b0f9af8965be9e17a9613665cda3d01fd628c876609e74ed6e23225383ad7983ed4e4160ccb565518520575ab6c56461e41d36339e64bbb99f179a9f693c46c13388d376a469b31457e56264fd72977a8505f3d8f9776fb66ba0ebd55f1833f1d8fbab4171b59f123102453fbc6a0f70b3dbf92021a5ad864c6373652504f99062e7019790d084549013a41cac50a25e1d8005a247ee6047ca33bea341f3f46919f8691648108c2f3707d76cd73b4a8692afd783e2323595e5b4c1720314a6b72ce56e0cbb33d933c88504bdd7ef791c57bcc70988e3ce7d165a2a6da8d54ee57ee248cd67976412fe11fa88f3f693dfe6972428ff918ba82f876f92f29463c6056e5de29687a4609518fbd98d5cb95ade44f8c58ba93cd49497afb770c50","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"12345678901234567890123456789012"};

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
