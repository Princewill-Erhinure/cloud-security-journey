# Incident Report: SSH Brute-Force and Server Compromise on web01

**Analyst:** Princewill Erhinure
**Date of incident:** 8 November 2026
**Severity:** Critical. The attacker gained full admin (root) access, stole
password hashes, created a backdoor account and downloaded a suspected
malicious script.

## 1. Summary
On 8 November 2026, the server web01 suffered a brute-force attack from IP
203.0.113.45. After 612 failed attempts, the attacker guessed the password
for the `deploy` account and logged in at 02:46. Once inside, they stole
password hashes, created a hidden user named `sysbackup` with admin rights,
and downloaded a suspicious file (/tmp/.x.sh) from their own server.
Urgent action: disable `deploy` and `sysbackup`, isolate the server and
reset all passwords. Long-term, SSH login should require public keys only.

## 2. Evidence reviewed
auth.log from server web01: 1,360 lines covering 8 November 2026 00:14 to
9 November 2026 00:03.

## 3. Timeline
| Time | Event | Stage |
|------|-------|-------|
| 02:11:10 | First failed login from 203.0.113.45 (612 attempts total) | Brute force |
| 02:46:11 | Last failed attempt | Brute force |
| 02:46:15 | Logs in as `deploy` with a guessed password | Initial access |
| 02:46:55 | Reads `/etc/shadow` | Credential theft |
| 02:47:25 | Creates hidden user `sysbackup` | Persistence |
| 02:47:45 | Adds `sysbackup` to the sudo (admin) group | Privilege escalation |
| 02:48:20 | Downloads `/tmp/.x.sh` from 203.0.113.45 | Tool / malware download |
| 02:48:55 | Logs out | Session ends |

## 4. Findings

**1. Brute-force attack from 203.0.113.45**
The log recorded 622 failed login attempts in total. Grouping them by IP
showed that 612 came from 203.0.113.45, which indicates a brute-force attack.
`grep "Failed password" auth.log | wc -l`
`grep "Failed password" auth.log | grep -o "from [0-9.]*" | sort | uniq -c | sort -nr`

**2. The attacker successfully logged in**
After the failed attempts, 203.0.113.45 logged in successfully as `deploy`
at 02:46:15 using a guessed password.
`grep "Accepted" auth.log | grep "203.0.113.45"`

**3. Malicious actions after login**
To see what the attacker did after logging in, I checked the lines after the
successful login and all admin (sudo) commands run by `deploy`. They read
password hashes, created a hidden admin account, and downloaded a suspected
malicious script.
`grep -A 8 "Accepted password for deploy" auth.log`
`grep "sudo" auth.log | grep "deploy"`

**4. Activity judged NOT part of the attack**
- 198.51.100.23 made 8 attempts in 31 seconds using generic usernames, never
  succeeded, and disconnected. This is an automated internet scanner.
- 10.0.0.12 failed twice, then logged in successfully from the same internal
  IP. This matches a staff member mistyping their password. Being internal does
  not automatically make an IP safe, but the pattern here is normal.

## 5. Impact
- **Stolen password hashes:** The attacker copied /etc/shadow. Weak
  passwords can be cracked offline and used to access other accounts on
  this server, and any other systems where staff reused those passwords.
- **Backdoor admin account:** The hidden account `sysbackup` has admin
  rights, so the attacker can return even after the `deploy` password is
  changed.
- **Full root control:** With admin power, the attacker could access or
  change anything on the server, including editing or deleting logs to hide
  their activity. The logs may not show everything that happened.
- **Suspected malware:** The downloaded script /tmp/.x.sh may still be
  running. The server "felt slow overnight," which could indicate a
  crypto-miner or other malicious process.

## 6. Indicators of Compromise (IOCs)
| Type | Value |
|------|-------|
| Attacker IP | 203.0.113.45 |
| Compromised account | deploy |
| Backdoor account | sysbackup |
| Malicious file | /tmp/.x.sh |
| Download URL | http://203.0.113.45/x.sh |

## 7. Response actions
- **Contain:** Block the attacker's IP (203.0.113.45). Disable the `deploy`
  and `sysbackup` accounts and end any active sessions to remove the
  attacker's access.
- **Eradicate:** Save a copy of /tmp/.x.sh for analysis, then delete it.
  Remove the `sysbackup` account. Check for anything else the attacker may
  have left, such as running processes, new cron jobs or added SSH keys.
- **Recover:** Change the passwords of all users, since all password hashes
  were stolen. Because the attacker had root access, rebuild the server from
  a clean backup taken before 8 November 2026, then monitor it closely for
  any return of the attacker.

## 8. Recommendations
- **Disable password login:** the attacker got in by guessing a password.
  SSH should only allow public key login.
- **Block repeated failures:** 612 attempts should never have been allowed.
  The server should automatically block an IP after a few failed attempts.
- **SIEM alerts:** set alerts for many failed logins from one IP, a
  successful login right after many failures, new user creation, and users
  being added to the sudo group.
- **Least privilege:** the `deploy` account should not have had admin access.
  Accounts should only have the access their job needs.

## 9. Tools and commands used
All analysis was done on the command line using Git Bash.

| Command | What it did in this investigation |
|---------|-----------------------------------|
| `wc -l auth.log` | Counted the lines to see how big the log was |
| `head` / `tail` | Showed the first and last lines to find the time range |
| `grep "text" auth.log` | Showed only lines containing specific text (e.g. "Failed password", "Accepted") |
| `\|` (pipe) | Sent one command's output into the next to chain steps together |
| `grep -o "from [0-9.]*"` | Pulled out only the IP addresses from each line |
| `sort \| uniq -c \| sort -nr` | Counted attempts per IP and ranked them highest first |
| `grep -A 8` | Showed the 8 lines after the attacker's login to see what they did next |
| `head -1` / `tail -1` | Found the first and last attempt to measure how long the attack lasted |