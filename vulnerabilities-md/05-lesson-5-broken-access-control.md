# Lesson #5: Broken Access Control

## Part 1) Goal and Vulnerability Summary

The DVSA-ORDER-MANAGER Lambda handles order actions through a switch statement but only the admin-orders case checks for admin privileges. The update action which calls DVSA-ORDER-UPDATE has no such check. This means any regular authenticated user can modify order contents without having to have admin permissions.

## Part 2) Why This Works / Root Cause

In order-manager.js the update case invokes DVSA-ORDER-UPDATE directly without checking isAdmin. The missing check means authorization is never checked for order updates.

## Part 3) Environment and Setup

API Endpoint: https://76lah627bi.execute-api.us-east-1.amazonaws.com/dvsa/order

Vulnerable Lambda: DVSA-ORDER-MANAGER in order-manager.js

Invoked Lambda: DVSA-ORDER-UPDATE

Database: DVSA-ORDERS-DB

Tools: curl , AWS Console

## Part 4) Reproduction Steps

Create a new order as a regular user with Pac-Man x1:

curl -s -X POST "%API%" -H "Content-Type: application/json" -H "authorization: %TOKEN%" -d "{\"action\":\"new\",\"cart-id\":\"cart-exploit\",\"items\":{\"Pac-Man\":1}}"

Without admin privileges call the update action to change items to Super Mario x5:

curl -s -X POST "%API%" -H "Content-Type: application/json" -H "authorization: %TOKEN%" -d "{\"action\":\"update\",\"order-id\":\"be968e25-99e9-492d-96ec-0234ee110369\",\"items\":{\"Super Mario\":5}}"

Verify in DynamoDB that items changed from Pac-Man to Super Mario without any payment.

## Part 5) Evidence and Proof

Figure 4 shows the regular user receiving a cart updated success response. The DynamoDB export confirmed the itemList changed from Pac-Man quantity 1 to Super Mario quantity 5 with totalAmount 0 and no payment processed.

*Figure 4. Regular user receives cart updated success. Exploit confirmed.*

The root cause is visible in the source code. The update case has no admin check while admin-orders does:

case "update":

payload = { "user": user, "orderId": req["order-id"], "items": req["items"] };

functionName = "DVSA-ORDER-UPDATE";

break;   // No isAdmin check

## Part 6) Fix Strategy / Probable Mitigation

Add the same isAdmin check to the update case that already exists in admin-orders. Any non-admin user calling update should receive HTTP 403. This enforces server-side authorization before invoking the privileged update function.

## Part 7) Code / Config Changes

The update case in order-manager.js was modified to include an admin check. Before the fix:

case "update":

payload = { "user": user, "orderId": req["order-id"], "items": req["items"] };

functionName = "DVSA-ORDER-UPDATE";

break;

After the fix:

case "update":

if (isAdmin == "true") {

payload = { "user": user, "orderId": req["order-id"], "items": req["items"] };

functionName = "DVSA-ORDER-UPDATE";

} else {

isOk = false;

const response = { statusCode: 403, headers: { "Access-Control-Allow-Origin": "*" },

body: JSON.stringify({"status": "err", "message": "Unauthorized"}) };

callback(null, response);

}

break;

## Part 8) Verification After Fix

The same exploit command now returns Unauthorized as shown in Figure 5. Regular users can no longer modify order contents.

*Figure 5. Unauthorized error returned after fix.*

## Part 9) Structured Operation and Security Analysis

Table A. Intended Logic and Exploit Behavior

| Vulnerability | Intended Rule(s) | Artifacts Used | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #5: Broken Access Control | Only admin users may invoke DVSA-ORDER-UPDATE to modify order items. Regular users may only view their own orders. | order-manager.js source code, curl API responses, DynamoDB DVSA-ORDERS-DB item scan | Regular user calling update should receive 403 Unauthorized. | Regular user called update action and received success. DynamoDB showed items changed from Pac-Man to Super Mario without payment. |

Table B. Deviation Analysis and Fix

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification |
| --- | --- | --- | --- | --- |
| Lesson #5: Broken Access Control | A regular user bypassed authorization and invoked an admin-only function. The update case had no isAdmin check. | Intentional misuse / security-relevant abuse | Lambda: DVSA-ORDER-MANAGER. Added isAdmin check to the update case with 403 response for non-admins. | Same exploit command now returns Unauthorized. Order items can no longer be modified by a regular user. |

## Part 10) Takeaway / Lessons Learned

Authorization must be enforced server-side on every sensitive action. Relying on the frontend to hide buttons is not a security control. In serverless systems every Lambda action is a direct API call that can be reached with curl regardless of what the UI shows.
