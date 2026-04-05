> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Web, #JavaScript, #APIEnumeration
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
6. [Lessons Learned](#lessons%20learned)
7. [References](#References)

---
## Introduction

**Objective:**
Analyze client-side JavaScript on a Smart Gnome Control registration form to identify a `resourceId` parameter used in API requests and exploit it to register or authenticate with elevated access.

**Description:**
The Smart Gnome Control web app presents a login and registration form powered by a custom `script.js` file. Reviewing the JavaScript reveals that the registration and username availability endpoints append a `resourceId` pulled from URL parameters or `localStorage`. Understanding how this ID is used enables manipulation of the registration flow.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #BrowserDevTools, #BurpSuite

---
## Enumeration

### Review the Application Structure
The page includes:
- Login form: `POST` to `/login` with `id`, `username`, `password`
- Register form: toggleable via a link, submits via `attemptRegister()`
- Username availability check: triggered on input via `checkUsername()`
- jQuery v3.7.1

### Analyze `script.js`

**`toggleForms()`**: Swaps the visible form between login and register.

**`getResourceId()`**: Retrieves `resourceId` from:
1. URL query parameter `?resourceId=...`
2. Falls back to `localStorage.getItem('resourceId')`

**`checkUsername(username)`**: Debounces input, then fetches:
```
/userAvailable?username=<input>&resourceId=<resourceId>
```

**`attemptRegister()`**: Constructs a fetch `POST` to:
```
/register?resourceId=<resourceId>
```
with body `JSON.stringify({ username, password })`.

**Key finding:** The `resourceId` is embedded in all API requests but is sourced entirely from client-controlled storage (URL params or localStorage). The server uses it to scope the registration to a specific resource — manipulating it may allow registration under a different resource context.

---
## Exploitation

### Manipulate the `resourceId`
Set a custom `resourceId` via the URL parameter when loading the page:

```
http://<target>/?resourceId=<target-resource-id>
```

Or set it directly in the browser console:
```javascript
localStorage.setItem('resourceId', '<target-resource-id>');
```

### Register Under the Target Resource
With the manipulated `resourceId` in place, complete the registration form. The `attemptRegister()` call will include the spoofed ID, potentially creating an account scoped to the target resource.

---
## Post-Exploitation/Flag

### Capturing the Flag
After registering with the manipulated `resourceId` and logging in, the flag is accessible through the authenticated interface.

---
## Lessons Learned

- **Client-side `resourceId` is not an access control boundary**: Any value sourced from URL parameters or `localStorage` is fully attacker-controlled. The server must validate that the requesting user is authorized to access or create resources under the provided ID.
- **JavaScript source review is essential**: Browser DevTools → Sources reveals business logic that would be hidden in a compiled application. Always review client-side JS for API endpoint names, parameter names, and authentication logic before testing a web app.
- **Insecure Direct Object Reference (IDOR)**: The `resourceId` pattern is a classic IDOR surface — if the server doesn't check authorization, any valid-looking ID can be used to access or modify another user's resources.
- **Debounce + fetch = real-time API calls**: The `checkUsername()` debounce pattern reveals that the `/userAvailable` endpoint exists and can be probed without submitting a full form, giving a low-noise way to enumerate valid usernames.

---
## References
- [OWASP IDOR – Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP – Client-side Storage](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1565 – Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [PortSwigger – IDOR](https://portswigger.net/web-security/access-control/idor)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
