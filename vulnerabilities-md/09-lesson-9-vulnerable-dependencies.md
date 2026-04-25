# Lesson #9: Vulnerable Dependencies

## Part 1) Goal and Vulnerability Summary

The DVSA application uses third-party dependencies that contain known security vulnerabilities. Specifically, the Lambda function relies on the node-serialize and node-jose libraries, both of which have documented high and critical security issues. These vulnerabilities may allow attackers to execute arbitrary code, perform command injection, or cause denial of service. The main weakness is the use of outdated or insecure dependencies without proper validation or updates.

## Part 2) Why This Works / Root Cause

The vulnerability exists because the application includes external libraries with known security flaws. These dependencies are not properly audited or updated, and the system assumes they are safe to use. In particular, node-serialize allows code execution through unsafe deserialization, and node-jose includes multiple vulnerabilities such as invalid curve attacks and command injection through its dependency chain.

## Part 3) Environment and Setup

Target: DVSA Lambda functions triggered by API

Vulnerable Libraries: node-serialize, node-jose

Environment: AWS Lambda (Node.js runtime)

Tools: AWS Console (code inspection), dependency analysis

## Part 4) Reproduction Steps

Navigate to AWS Console → Lambda.

Open a Lambda function triggered by the DVSA API.

Go to the Code section.

Identify imported dependencies such as node-serialize and node-jose.

Cross-reference these libraries with known vulnerability databases.

Confirm that these dependencies contain critical and high-risk vulnerabilities.

## Part 5) Evidence and Proof

The Lambda function configuration shows that the application depends on vulnerable third-party libraries, including node-serialize and node-jose. These dependencies are known to contain critical security vulnerabilities, confirming the presence of insecure external components in the system.

*Figure 30. package.json showing usage of vulnerable dependencies node-serialize and node-jose.*

## Part 6) Fix Strategy / Probable Mitigation

The application must remove or replace vulnerable dependencies such as node-serialize and node-jose with secure and actively maintained alternatives. Regular dependency auditing and updates ensure that known vulnerabilities are not present in the system.

## Part 7) Code / Config Changes

The vulnerable dependencies were updated by removing node-serialize, which is not required and introduces a critical code execution vulnerability, and replacing node-jose with a secure and actively maintained alternative (jose). This ensures that the application no longer relies on insecure dependencies.

### Before fix:

{

"name": "order-manager",

"version": "3.0.0",

"main": "order-manager.js",

"dependencies": {

"node-jose": "2.2.0",

"node-serialize": "0.0.4"

},

"scripts": {

"test": "echo \"Error: no test specified\" && exit 1"

},

"author": "",

"license": "ISC",

"description": ""

}

### After fix:

{

"name": "order-manager",

"version": "3.0.0",

"main": "order-manager.js",

"dependencies": {

"jose": "^5.0.0"

},  "scripts": {

"test": "echo \"Error: no test specified\" && exit 1"

},

"author": "",

"license": "ISC",

"description": ""

}

### Before fix:

const serialize = require('node-serialize');

const jose = require('node-jose');

var req = serialize.unserialize(event.body);

var headers = serialize.unserialize(event.headers);

var token_sections = auth_header.split('.');

var auth_data = jose.util.base64url.decode(token_sections[1]);

var token = JSON.parse(auth_data);

after fix:

const { decodeJwt } = require('jose');

const { LambdaClient, InvokeCommand } = require("@aws-sdk/client-lambda");

const { CognitoIdentityProviderClient, AdminGetUserCommand } = require("@aws-sdk/client-cognito-identity-provider");

exports.handler = (event, context, callback) => {

var req = JSON.parse(event.body);

var headers = event.headers;

var auth_header = headers.Authorization || headers.authorization;

var token = decodeJwt(auth_header);

var user = token.username;

var isAdmin = false;

## Part 8) Verification After Fix

After applying the fix, the application no longer includes the vulnerable dependencies node-serialize and node-jose in its configuration. The updated package.json confirms that these insecure libraries have been removed and replaced with a secure alternative (jose). As a result, the application is no longer exposed to the previously identified vulnerabilities such as code execution, command injection, and denial of service.

*Figure 31. The updated dependency configuration with only the secure library present, confirming that vulnerable dependencies have been successfully eliminated.*

## Part 9) Structured Operation and Security Analysis

Table A. Intended Logic and Exploit Behavior

| Vulnerability | Intended Rule(s) | Artifacts Used | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #9: Vulnerable Dependencies | The application should only use secure, trusted, and actively maintained third-party libraries. Dependencies must not contain known vulnerabilities. | Lambda function code, package.json file, vulnerability reports | Dependencies should be updated, audited, and free from known critical or high-risk vulnerabilities. | The package.json file shows usage of node-serialize and node-jose, which contain known vulnerabilities such as code execution, command injection, and denial of service. |

Table B. Deviation Analysis and Fix

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification |
| --- | --- | --- | --- | --- |
| Lesson #9: Vulnerable Dependencies | The application includes third-party libraries with known vulnerabilities, violating the requirement to use secure and maintained dependencies. This exposes the system to potential exploitation through external code. | Accidental misconfiguration / insecure dependency management | package.json: Removed node-serialize and replaced node-jose with a secure alternative (jose). | Updated package.json shows only secure dependencies, and no vulnerable libraries are present in the application configuration. |

## Part 10) Takeaway / Lessons Learned

This vulnerability highlights the risks of using third-party dependencies without proper security validation. Even if the application code is secure, vulnerable libraries can introduce critical weaknesses such as code execution and injection attacks. Regular dependency auditing, timely updates, and replacing insecure libraries with trusted alternatives are essential practices to maintain a secure application.
