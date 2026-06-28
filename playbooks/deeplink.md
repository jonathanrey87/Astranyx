# Deep Link Testing Playbook

## Objective
Determine whether custom URL schemes expose unauthorized functionality.

## Preparation
- Record app name
- Record bundle ID
- Record app version
- Record device version
- Record login state
- Identify URL schemes

## Test Cases
1. Open base scheme while logged out.
2. Open login route while logged out.
3. Open callback route while logged out.
4. Repeat while logged in.
5. Compare behavior.

## Evidence Checklist
- Screenshots
- Requests
- Responses
- Notes
- Timeline entry

## Expected Security Behavior
- Authentication is enforced.
- Authorization is enforced.
- Sensitive data is not exposed.
