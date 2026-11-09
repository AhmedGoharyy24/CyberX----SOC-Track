# SOC Investigation Report — Password Guessing & Process Execution

**Student:**  
**Date:**  
**Evidence:** `SOC_Session02_Investigation.evtx`

## Scenario
A Windows workstation recorded repeated failed authentication attempts against a local account, followed by a successful logon. Afterward, multiple processes were created under different security contexts. Investigate the authentication sequence and the process-creation evidence using Windows Event Viewer.

## Part A — Authentication (4624 / 4625)
1. Which account was targeted?
2. How many failed logons occurred? Record timestamps and Event Record IDs.
3. Was there a successful logon after the failures? Provide its timestamp and Record ID.
4. What is the Logon Type? Explain its meaning.
5. Record the Status and SubStatus values from the failed logons.
6. What source IP address and workstation information are recorded? If a field is empty or loopback, state that rather than guessing.

## Part B — Process creation (4688)
7. Identify at least three process-creation events. Record `New Process Name`, `Creator Process Name`, `Process ID`, and `Process Command Line` when available.
8. Compare the `SubjectUserName` values. Which processes are associated with the temporary standard account and which with the administrator account?
9. What `Token Elevation Type` values appear? Explain each value you actually observe:
   - `%%1936` — Type 1, Default
   - `%%1937` — Type 2, Full
   - `%%1938` — Type 3, Limited
10. Is there evidence of an elevated process? Cite the exact 4688 Record ID and token field.
11. Are the recorded command lines consistent with the stated lab activity? Explain.

## Timeline
| Timestamp | Event ID | Account / Process | Result | Record ID / Evidence |
|---|---:|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

## Final assessment
**Authentication finding:**  
**Process-creation finding:**  
**Evidence supporting the assessment:**  
**What cannot be concluded from these logs alone:**  
**Recommended next SOC investigation step:**  
