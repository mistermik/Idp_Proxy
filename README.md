# Okta – Entra Device Compliance Proxy

## Overview

Okta Device Assurance currently **cannot directly consume device compliance signals from Microsoft Entra / Intune**.  
Microsoft exposes these signals only in the **access token**, while Okta integrations typically rely on the **ID token** or **UserInfo endpoint**.

As a result, Okta cannot easily enforce device posture checks using Entra-managed device signals.

⚠️ **Impact:**  
Users may successfully authenticate through Okta **even when their device is not compliant or managed**, because Okta cannot see the relevant posture attributes.

---

## The Idea

To solve this, we introduce a **Proxy Identity Provider** between **Okta** and **Microsoft Entra**.

The proxy participates in the OpenID Connect flow and enriches the identity information returned to Okta.

### Flow

1. User authenticates via Okta.
2. Okta redirects authentication to the **Proxy IdP**.
3. The Proxy redirects the user to **Microsoft Entra**.
4. Entra returns:
   - `id_token` → user identity
   - `access_token` → contains device posture signals
5. The Proxy extracts device claims such as:
   - `dvc_mngd`
   - `dvc_cmp`
6. The Proxy issues a **new `id_token`** back to Okta containing enriched device posture data.

This allows **Okta Device Assurance policies** to evaluate the device state.

---

## Architecture

<img width="2618" height="1665" alt="architecture" src="https://github.com/user-attachments/assets/840053f4-eaa8-463f-876b-fbb73454014f" />

---

## Key Features

### Token Enrichment

The proxy adds a **`device_context` claim** to the ID token returned to Okta.

Example:

```json
{
  "device_context": {
    "managed": true,
    "compliant": true,
    "externalId": "123"
  }
}
