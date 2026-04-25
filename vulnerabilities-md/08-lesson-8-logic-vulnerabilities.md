# Lesson #8: Logic Vulnerabilities

## Part 1) Goal and Vulnerability Summary

The DVSA order workflow contains a logic vulnerability due to a race condition between the billing and update actions. After submitting a billing request, it is still possible to send an update request to modify the order contents. This allows an attacker to pay for fewer items while receiving more, violating the intended business logic of the application.

## Part 2) Why This Works / Root Cause

The vulnerability exists because the system does not enforce a strict order state after billing. The update action can still be executed even after the payment is processed. There is no locking or validation to prevent modifications to an order once it has been billed, resulting in a time-of-check to time-of-use (TOCTOU) race condition.

## Part 3) Environment and Setup

API Endpoint: https://76lah627bi.execute-api.us-east-1.amazonaws.com/dvsa/order

Vulnerable Components: DVSA-ORDER-BILLING and DVSA-ORDER-MANAGER

Database: DVSA-ORDERS-DB

Tools: curl, AWS Console

## Part 4) Reproduction Steps

Navigate to the DVSA website and log in:
http://dvsa-website-test1-124074139994-us-east-1.s3-website.us-east-1.amazonaws.com

Add one item to the cart (e.g., Adidas DRI) and proceed through checkout until the order is created.

Open Developer Tools (F12) → Application → Local Storage and copy the value of order-id.

Open a Linux terminal (WSL) and set the API endpoint and token:

API="https://76lah627bi.execute-api.us-east-1.amazonaws.com/dvsa/order"
TOKEN="PASTE_YOUR_TOKEN_HERE"

Open two terminals to prepare concurrent requests.

In the first terminal, send the billing request:

curl -s -X POST "$API" \

-H "Content-Type: application/json" \

-H "authorization: $TOKEN" \

-d "{\"action\":\"billing\",\"order-id\":\"$ORDER_ID\",\"data\":{\"ccn\":\"378282246310005\",\"exp\":\"02/28\",\"cvv\":\"333\"}}"

In the second terminal, prepare the update request:

curl -s -X POST "$API" \

-H "Content-Type: application/json" \

-H "authorization: $TOKEN" \

-d "{\"action\":\"update\",\"order-id\":\"$ORDER_ID\",\"items\":{\"$NAME \":5}}"

Execute the race condition by pressing Enter in the billing terminal, and immediately after pressing Enter in the update terminal without waiting for the billing response.

Verify the final order state by checking the website or querying the DynamoDB table DVSA-ORDERS-DB.

Observe that the order quantity has increased after billing while the charged amount remains unchanged, confirming the race condition vulnerability.

## Part 5) Evidence and Proof

The billing response shows payment for a single item, but after sending an update request immediately after, the final order reflects a higher quantity while the total amount remains unchanged, confirming the race condition vulnerability.

*Figure 24. The billing response confirming that the payment was processed for a single item only.*

*Figure 25. The update request modifying the order quantity immediately after billing.*

*Figure 26. The final order or DynamoDB record where the item quantity is increased while the total charged amount remains unchanged, confirming the successful exploitation of the race condition vulnerability.*

## Part 6) Fix Strategy / Probable Mitigation

The application must enforce strict order state validation to prevent modifications after payment. Once a billing request is processed, the order should be marked as finalized (e.g., status = “PAID”), and any subsequent update requests must be rejected. Additionally, the system should ensure atomic processing of billing and order updates to eliminate race conditions. This prevents attackers from modifying order contents after payment and preserves the integrity of the transaction.

## Part 7) Code / Config Changes

The update action in the order workflow was modified to include a validation check that prevents order modifications after payment, ensuring that once billing is completed, the order contents cannot be changed.

Before the fix:

case "update":

payload = { "user": user, "orderId": req["order-id"], "items": req["items"] };

functionName = "DVSA-ORDER-UPDATE";

break;

after fix:

case "update":

if (orderStatus == "PAID") {

isOk = false;

const response = {

statusCode: 403,

headers: { "Access-Control-Allow-Origin": "*" },

body: JSON.stringify({

"status": "err",

"message": "Order cannot be modified after payment"

})

};

callback(null, response);

} else {

payload = { "user": user, "orderId": req["order-id"], "items": req["items"] };

functionName = "DVSA-ORDER-UPDATE";

}

break;

## Part 8) Verification After Fix

*Figure 27. Billing request showing successful payment for the original order amount.*

*Figure 28. Update request attempting to modify the order after billing.*

*Figure 29. DynamoDB record showing the order remains unchanged after billing, confirming that post-payment updates are no longer allowed.*

## Part 9) Structured Operation and Security Analysis

Table A. Intended Logic and Exploit Behavior

| Vulnerability | Intended Rule(s) | Artifacts Used | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Lesson #8: Logic Vulnerabilities | Once an order is billed, it must not be modified. Order updates should only be allowed before payment is completed. | API requests (billing, update), DynamoDB records, DVSA order workflow | After billing, any update request should be rejected and the order should remain unchanged. | The update request was accepted immediately after billing, allowing modification of the order contents before finalization, resulting in a mismatch between paid amount and final order items. |

Table B. Deviation Analysis and Fix

| Vulnerability | Why This Is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification |
| --- | --- | --- | --- | --- |
| Lesson #8: Logic Vulnerabilities | The system allowed an order to be updated after payment was processed, violating the intended workflow that locks the order after billing. This enables manipulation of order contents after payment. | Accidental misconfiguration / insecure workflow design | DVSA-ORDER-MANAGER: Added validation in the update action to reject requests if the order status is already paid. | After the fix, update requests sent after billing return an error, and the order remains unchanged, ensuring consistency between payment and final order state. |

## Part 10) Takeaway / Lessons Learned

This vulnerability highlights the importance of enforcing proper workflow state and sequencing in application logic. Even when individual functions operate correctly, failing to restrict actions based on the current state of an order can lead to serious business logic flaws. Ensuring that critical operations such as payment finalize and lock the resource prevents attackers from exploiting race conditions to manipulate outcomes.
