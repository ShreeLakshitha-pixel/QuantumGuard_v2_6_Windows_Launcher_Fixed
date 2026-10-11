/**
 * Microservice Authentication and JWT Token Issuer.
 * Generates asymmetric keys and signs JWT authorization tokens.
 */
const crypto = require('crypto');

function generateIssuerKeys() {
    // Generates 2048-bit RSA keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

function signAuthorizationHeader(userId, privateKey) {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString('base64');
    const payload = Buffer.from(JSON.stringify({ sub: userId, role: "admin", iat: Date.now() })).toString('base64');
    
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(`${header}.${payload}`);
    const signature = signer.sign(privateKey, 'base64');
    
    return `${header}.${payload}.${signature}`;
}

module.exports = { generateIssuerKeys, signAuthorizationHeader };
