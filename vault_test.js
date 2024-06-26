import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

let authFailures = new Counter('auth_failures');
let encryptFailures = new Counter('encrypt_failures');
let decryptFailures = new Counter('decrypt_failures');


const VAULT_ADDR = __ENV.VAULT_ADDR || 'http://127.0.0.1:8200';
const ROLE_ID = __ENV.ROLE_ID;
const SECRET_ID = __ENV.SECRET_ID;
const TRANSIT_KEY_NAME = __ENV.TRANSIT_KEY_NAME || 'my-key';
const NAMESPACE =  __ENV.NAMESPACE;

let authToken;

// Base64 encoding function compatible with k6
function base64Encode(str) {
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let encoded = '';
    let c1, c2, c3;
    let e1, e2, e3, e4;

    for (let i = 0; i < str.length;) {
        c1 = str.charCodeAt(i++);
        c2 = str.charCodeAt(i++);
        c3 = str.charCodeAt(i++);

        e1 = c1 >> 2;
        e2 = ((c1 & 3) << 4) | (c2 >> 4);
        e3 = ((c2 & 15) << 2) | (c3 >> 6);
        e4 = c3 & 63;

        if (isNaN(c2)) {
            e3 = e4 = 64;
        } else if (isNaN(c3)) {
            e4 = 64;
        }

        encoded += chars.charAt(e1) + chars.charAt(e2) + chars.charAt(e3) + chars.charAt(e4);
    }

    return encoded;
}

// Base64 decoding function compatible with k6
function base64Decode(str) {
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let decoded = '';
    let c1, c2, c3;
    let e1, e2, e3, e4;

    for (let i = 0; i < str.length;) {
        e1 = chars.indexOf(str.charAt(i++));
        e2 = chars.indexOf(str.charAt(i++));
        e3 = chars.indexOf(str.charAt(i++));
        e4 = chars.indexOf(str.charAt(i++));

        c1 = (e1 << 2) | (e2 >> 4);
        c2 = ((e2 & 15) << 4) | (e3 >> 2);
        c3 = ((e3 & 3) << 6) | e4;

        decoded += String.fromCharCode(c1);

        if (e3 !== 64) {
            decoded += String.fromCharCode(c2);
        }
        if (e4 !== 64) {
            decoded += String.fromCharCode(c3);
        }
    }

    return decoded;
}

// Function to generate a random string of a given length
function generateRandomString(length) {
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Function to authenticate with Vault using AppRole and fetch token
function authWithAppRole() {
    const url = `${VAULT_ADDR}/v1/auth/approle/login`;
    const payload = JSON.stringify({
        role_id: ROLE_ID,
        secret_id: SECRET_ID,
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'X-Vault-Namespace': NAMESPACE,
        },
    };

    let res = http.post(url, payload, params);
    if (res.status === 200) {
        authToken = res.json().auth.client_token;
    } else {
        authFailures.add(1);
        console.error(`Authentication failed: ${res.status_text}`);
    }
}

// Function to encrypt data using the Transit secrets engine
function encryptData(plaintext) {
    const url = `${VAULT_ADDR}/v1/transit/encrypt/${TRANSIT_KEY_NAME}`;
    const payload = JSON.stringify({
        plaintext: base64Encode(plaintext),
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'X-Vault-Token': authToken,
            'X-Vault-Namespace': NAMESPACE,
        },
    };

    let res = http.post(url, payload, params);
    if (res.status === 200) {
        return res.json().data.ciphertext;
    } else {
        encryptFailures.add(1);
        console.error(`Encryption failed: ${res.status_text}`);
        return null;
    }
}

// Function to decrypt data using the Transit secrets engine
function decryptData(ciphertext) {
    const url = `${VAULT_ADDR}/v1/transit/decrypt/${TRANSIT_KEY_NAME}`;
    const payload = JSON.stringify({
        ciphertext: ciphertext,
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'X-Vault-Token': authToken,
            'X-Vault-Namespace': NAMESPACE,
        },
    };

    let res = http.post(url, payload, params);
    if (res.status === 200) {
        return base64Decode(res.json().data.plaintext);
    } else {
        decryptFailures.add(1);
        console.error(`Decryption failed: ${res.status_text}`);
        return null;
    }
}

export let options = {
   vus: 20, // Number of virtual users
   duration: '2m', // Duration of the test
	// stages: [
    // 	   { duration: '30s', target: 500 },
    //        { duration: '30s', target: 1000 },
    //        { duration: '30s', target: 1500 },
    //        { duration: '30s', target: 2000 },
	// ]
};

// Authenticate with Vault and fetch token

export default function () {
    if (!authToken) {
        authWithAppRole();
    }
    if (authToken) {
        const plaintext = generateRandomString(256);
        console.log(`Generated plaintext: ${plaintext}`);
        const ciphertext = encryptData(plaintext);
	if (ciphertext) {
		const decryptedText = decryptData(ciphertext);
		check(decryptedText, {
			'decrypted text matches': (text) => text === plaintext,
		});
	}
    }
    sleep(1);
}