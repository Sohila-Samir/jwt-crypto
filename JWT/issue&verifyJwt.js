const crypto = require('crypto')
const fs = require('fs')
const base64url = require('base64url')
const createSignFunction = crypto.createSign('RSA-SHA256')
const verifyFunction = crypto.createVerify('RSA-SHA256')

// ---------------------------Variables needed for Issuing process--------------------------------------

const privateKey = fs.readFileSync(__dirname + '/PRV_KEY.pem', 'utf-8');
const publicKey = fs.readFileSync(__dirname + '/PUB_KEY.pem', 'utf-8');

const payloadString = JSON.stringify(
{
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
})

const headerString = JSON.stringify(
{
"alg": "HS256",
"typ": "JWT"
}
)
// -----------------------------------------Issuing------------------------------------------------

const headerBase64Url = base64url(headerString)
const payloadBase64Url = base64url(payloadString)


createSignFunction.write(headerBase64Url + '.' + payloadBase64Url)
createSignFunction.end()


const signatureBase64 = createSignFunction.sign(privateKey, 'base64')
const signatureBase64Url = base64url.fromBase64(signatureBase64)

const jwt = [headerBase64Url, payloadBase64Url, signatureBase64Url].join('.')
console.log(`issued jwt: ${jwt}`);

// ---------------------------Variables needed for Verification process--------------------------------------

const jwtParts = jwt.split('.')

const jwtHeader = jwtParts[0]
const jwtPayload = jwtParts[1]
const jwtSignature = jwtParts[2]

// -------------------------------------Verification------------------------------------------

verifyFunction.write(jwtHeader + '.' + jwtPayload)
verifyFunction.end()

const jwtSignatureBase64 = base64url.toBase64(jwtSignature, 'base64')

const isValidSignature = verifyFunction.verify(publicKey, jwtSignatureBase64, 'base64')

console.log(`Jwt after verification: ${isValidSignature}`);