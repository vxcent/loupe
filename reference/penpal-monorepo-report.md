# PenPal Security Analysis Report

**Workspace:** `virse-systems-monorepo`
**Generated:** 2026-04-23 18:02:06
**Analyst:** zinuox
**PenPal Version:** 1.3.1b0
**Profile:** web

> **DISCLAIMER:** PenPal is an experimental AI tool that may miss vulnerabilities, report false positives, or recommend ineffective fixes. It does not replace professional security review. Validate all findings independently.

## Executive Summary

| Metric | Value |
|--------|-------|
| Entrypoints Scanned | 165 |
| CWE Checks | 13 |
| Total Analyses | 2,067 |
| Flagged Issues | 111 |
| Validated (Plausible) | 59 |
| QA Confirmed | 59 |
| Duplicates Removed | 6 |
| **Unique Confirmed** | **53** |

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 11 |
| Medium | 27 |
| Low | 8 |
| **Total** | **53** |

## Vulnerability Findings

| # | Severity | CVSS | CWE | Title | Location |
|---|----------|------|-----|-------|----------|
| 1 | Critical | 10.0 | CWE-798 | Hard-coded Credentials Committed Across Repository (GCP Service Account, Internal Admin API Key, Third-Party API Keys) | `backend/billing_service/billing_app.py:468` |
| 2 | Critical | 9.9 | CWE-306 | Missing Authentication in `verify_invitation` Enables Account Takeover via Email | `backend/user_service/user_app.py:142` |
| 3 | Critical | 9.4 | CWE-863 | Missing Authorization in update_space_permission Endpoint Allows Space Takeover | `backend/permission_service/permission_app.py:100` |
| 4 | Critical | 9.4 | CWE-863 | Missing Caller Authorization in OAuth Consent Form Handler | `backend/oauth_service/oauth_login.py:686` |
| 5 | Critical | 9.3 | CWE-863 | Missing Authorization in `update_organization_permission` Endpoint | `backend/permission_service/permission_app.py:157` |
| 6 | Critical | 9.3 | CWE-306 | Missing Authentication on `/image_project_callback` Endpoint | `backend/image_service/image_app.py:1092` |
| 7 | Critical | 9.1 | CWE-310 | Use of Non-Cryptographic PRNG for Verification Codes and OAuth Device `user_code` | `backend/user_service/verification_service.py:25, backend/oauth_service/oauth_engine.py:285` |
| 8 | High | 8.8 | CWE-863 | Missing Authorization on `/image_project_callback` Allows Forged Asset Ownership | `backend/image_service/image_app.py:1092` |
| 9 | High | 8.8 | CWE-863 | Missing Authentication on Billing `/internal/*` Endpoints | `backend/billing_service/billing_app.py:216` |
| 10 | High | 8.7 | CWE-863 | Missing Authorization in `/get_user_details` Enables Unauthenticated PII and Invitation Code Disclosure | `backend/getinfo_service/getinfo_app.py:358` |
| 11 | High | 7.6 | CWE-863 | Missing Authorization in invite_user_endpoint Allows Any Authenticated User to Add Members to Arbitrary Spaces | `backend/permission_service/permission_app.py:306` |
| 12 | High | 7.6 | CWE-942 | Permissive CORS Regex Accepting Attacker-Controlled Origins in Backend FastAPI App | `backend/app.py:133` |
| 13 | High | 7.6 | CWE-863 | Missing Authorization (IDOR) in Image, Text, and Engine Endpoints via Existence-Only Validators | `db_service/utils.py:59` |
| 14 | High | 7.4 | CWE-319 | Cleartext Transmission of OAuth Credentials and Auth Tokens in Backend Services | `backend/inner_requests.py:56` |
| 15 | High | 7.2 | CWE-863 | Missing Authorization on org_id in POST /billing/internal/consume | `backend/billing_service/billing_app.py:216` |
| 16 | High | 7.2 | CWE-22 | Path Traversal via Unsanitized `request-id` Header in Image Upload and Generation Endpoints | `backend/inner_requests.py:58` |
| 17 | High | 7.2 | CWE-863 | Missing Image-Ownership Authorization in `update_image_permission` Endpoint | `backend/permission_service/permission_app.py:27` |
| 18 | High | 7.1 | CWE-863 | Missing Authorization in `/update_human_eval` Moderation Endpoint | `image_register_project/app.py:114` |
| 19 | Medium | 9.1 | CWE-307 | Missing Brute-Force Protection on Authentication Endpoints | `backend/user_service/user_app.py:718` |
| 20 | Medium | 8.8 | CWE-863 | Missing Authorization on Rating Queue Endpoints in image_caption_app.py | `search_project/image_caption_app.py:224` |
| 21 | Medium | 8.2 | CWE-306 | Missing Authentication on Form Branch of `POST /device/consent` | `backend/oauth_service/oauth_login.py:994` |
| 22 | Medium | 7.1 | CWE-863 | Missing Authorization on Canvas Project Read Endpoints | `backend/canvas_service/canvas_app.py:58` |
| 23 | Medium | 6.9 | CWE-863 | Missing Authorization on Canvas WebSocket Stats Endpoint | `backend/canvas_service/canvas_app.py:543` |
| 24 | Medium | 6.9 | CWE-306 | Missing Authentication in POST /get_user_details Enables User Enumeration and PII Disclosure | `backend/getinfo_service/getinfo_app.py:358` |
| 25 | Medium | 6.9 | CWE-306 | Missing Authentication on `/recall_by_image` Enables Resource-Exhaustion DoS | `search_project/image_search_app.py:77` |
| 26 | Medium | 6.9 | CWE-918 | Unauthenticated Server-Side Request Forgery via /register_multiple_images URL Queue | `image_register_project/app.py:187` |
| 27 | Medium | 6.9 | CWE-22 | Path Traversal in search_project Image Path Handling | `search_project/image_utils.py:97` |
| 28 | Medium | 6.9 | CWE-918 | Server-Side Request Forgery in `/recall_by_image` Endpoint | `search_project/image_search_app.py:77` |
| 29 | Medium | 6.9 | CWE-863 | Missing Authentication on State-Changing Endpoints in image_register_project | `image_register_project/app.py:150` |
| 30 | Medium | 6.9 | CWE-863 | Missing Authorization in Project WebSocket Endpoint | `backend/websocket_app.py:19` |
| 31 | Medium | 6.8 | CWE-532 | Authentication Tokens Logged via Full Request Headers in Token Verification Helpers | `backend/user_service/user_app.py:132` |
| 32 | Medium | 6.3 | CWE-918 | Server-Side Request Forgery in get_response_from_url Helper | `image_project/image_generator/utils/__init__.py:92, lamm_project/engine.py:19` |
| 33 | Medium | 6.1 | CWE-863 | Missing Authorization in update_style_permission Endpoint | `backend/permission_service/permission_app.py:630` |
| 34 | Medium | 6.1 | CWE-863 | Missing Authorization in `delete_workflow_template` Endpoint | `backend/create_service/create_app.py:237` |
| 35 | Medium | 6.1 | CWE-863 | Owner Authorization Bypass in Stripe `_require_org_owner` Default-Org Path | `backend/stripe_service/stripe_engine.py:80` |
| 36 | Medium | 6.0 | CWE-863 | Missing Per-Caller Authorization (IDOR) Across Getinfo Service Read Endpoints | `backend/getinfo_service/getinfo_app.py:22` |
| 37 | Medium | 5.3 | CWE-863 | Missing Space-Level Authorization in verify_invite_user Endpoint Enables User and Membership Enumeration | `backend/permission_service/permission_app.py:402` |
| 38 | Medium | 5.3 | CWE-863 | Missing Authorization on Organization Update Path in `create_organization_endpoint` | `backend/create_service/create_app.py:79` |
| 39 | Medium | 5.3 | CWE-918 | Server-Side Request Forgery in /recall_images Image Fetch | `search_project/app.py:79` |
| 40 | Medium | 5.3 | CWE-863 | Missing Authorization in `/get_pending_images` Moderation Queue Endpoint | `image_register_project/app.py:73` |
| 41 | Medium | 5.1 | CWE-918 | Server-Side Request Forgery via Unvalidated `reference_image_urls` in `/enhance_query_with_references` | `agent_project/app.py:106` |
| 42 | Medium | 5.1 | CWE-918 | Server-Side Request Forgery in /compute_aesthetic_summary Image URL Handler | `lamm_project/app.py:36` |
| 43 | Medium | 4.8 | CWE-434 | Unrestricted File Upload in `/upload_images` Endpoint Allows HTML/SVG Hosting on Public GCS Bucket | `backend/app.py:212` |
| 44 | Medium | 2.3 | CWE-863 | Missing Ownership Check in Style Update Path of create_style_endpoint | `backend/create_service/create_app.py:128` |
| 45 | Medium | 2.3 | CWE-863 | Missing Cross-Tenant Authorization in `api_upload_image` Canvas-Placement Branch | `mcp_project/app.py:275` |
| 46 | Low | 6.9 | CWE-863 | Missing Authorization on WebSocket Stats Telemetry Endpoint | `backend/websocket_app.py:161` |
| 47 | Low | 5.7 | CWE-526 | Cleartext Storage of Secrets in Environment Variables | `backend/stripe_service/stripe_config.py:13` |
| 48 | Low | 5.3 | CWE-601 | Open Redirect in OAuth Callback Bridge Page | `backend/oauth_service/oauth_login.py:383` |
| 49 | Low | 2.3 | CWE-79 | DOM-based XSS via Unvalidated URL Scheme in OAuth Callback Bridge | `backend/oauth_service/oauth_login.py:383` |
| 50 | Low | 2.3 | CWE-863 | Missing Authorization in create_workflow_template Endpoint | `backend/create_service/create_app.py:192` |
| 51 | Low | 2.3 | CWE-863 | Missing Authorization in get_workflow_template Endpoint Allows Cross-User Template Disclosure | `backend/create_service/create_app.py:279` |
| 52 | Low | 2.1 | CWE-749 | Exposed SSRF Primitive via Unrestricted `upload_image` MCP Tool | `mcp_project/tools/image_tools.py:178` |
| 53 | Low | 2.1 | CWE-1021 | Missing Clickjacking Protections on OAuth Consent and Login Pages | `` |

## Detailed Findings

### 1. Hard-coded Credentials Committed Across Repository (GCP Service Account, Internal Admin API Key, Third-Party API Keys)

- **Severity:** Critical
- **CVSS 4.0:** 10.0
- **CWE:** CWE-798
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:H`
- **Location:** `backend/billing_service/billing_app.py:468`
- **Source:** Workspace × CWE-798
- **QA Status:** Confirmed

### 2. Missing Authentication in `verify_invitation` Enables Account Takeover via Email

- **Severity:** Critical
- **CVSS 4.0:** 9.9
- **CWE:** CWE-306
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N`
- **Location:** `backend/user_service/user_app.py:142`
- **Source:** Global::verify_invitation(VerifyInvitationRequest, Request) -> Response × CWE-306
- **QA Status:** Confirmed

### 3. Missing Authorization in update_space_permission Endpoint Allows Space Takeover

- **Severity:** Critical
- **CVSS 4.0:** 9.4
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L`
- **Location:** `backend/permission_service/permission_app.py:100`
- **Source:** Global::update_space_permission(UpdateSpacePermissionRequest, Request, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 4. Missing Caller Authorization in OAuth Consent Form Handler

- **Severity:** Critical
- **CVSS 4.0:** 9.4
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L`
- **Location:** `backend/oauth_service/oauth_login.py:686`
- **Source:** Global::consent_submit(Request) -> Response × CWE-863
- **QA Status:** Confirmed

### 5. Missing Authorization in `update_organization_permission` Endpoint

- **Severity:** Critical
- **CVSS 4.0:** 9.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Location:** `backend/permission_service/permission_app.py:157`
- **Source:** Global::update_organization_permission(UpdateOrganizationPermissionRequest, Request) -> Response × CWE-863
- **QA Status:** Confirmed

### 6. Missing Authentication on `/image_project_callback` Endpoint

- **Severity:** Critical
- **CVSS 4.0:** 9.3
- **CWE:** CWE-306
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:N`
- **Location:** `backend/image_service/image_app.py:1092`
- **Source:** Global::backend_callback(Request) -> Response × CWE-306
- **QA Status:** Confirmed

### 7. Use of Non-Cryptographic PRNG for Verification Codes and OAuth Device `user_code`

- **Severity:** Critical
- **CVSS 4.0:** 9.1
- **CWE:** CWE-310
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/user_service/verification_service.py:25, backend/oauth_service/oauth_engine.py:285`
- **Source:** Systemic: Use of non-cryptographic PRNG (python random module) for security-sensitive tokens × CWE-310
- **QA Status:** Confirmed

### 8. Missing Authorization on `/image_project_callback` Allows Forged Asset Ownership

- **Severity:** High
- **CVSS 4.0:** 8.8
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:L/SA:N`
- **Location:** `backend/image_service/image_app.py:1092`
- **Source:** Global::backend_callback(Request) -> Response × CWE-863
- **QA Status:** Confirmed

### 9. Missing Authentication on Billing `/internal/*` Endpoints

- **Severity:** High
- **CVSS 4.0:** 8.8
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Location:** `backend/billing_service/billing_app.py:216`
- **Source:** Systemic: Billing `/internal/*` endpoints missing authentication/authorization × CWE-863
- **QA Status:** Confirmed

### 10. Missing Authorization in `/get_user_details` Enables Unauthenticated PII and Invitation Code Disclosure

- **Severity:** High
- **CVSS 4.0:** 8.7
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:L/SA:N`
- **Location:** `backend/getinfo_service/getinfo_app.py:358`
- **Source:** Global::get_user_details(Request, GetUserDetailsRequest, Optional[str]) -> Response × CWE-863
- **QA Status:** Confirmed

### 11. Missing Authorization in invite_user_endpoint Allows Any Authenticated User to Add Members to Arbitrary Spaces

- **Severity:** High
- **CVSS 4.0:** 7.6
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/permission_service/permission_app.py:306`
- **Source:** Global::invite_user_endpoint(InviteUserRequest, Request, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 12. Permissive CORS Regex Accepting Attacker-Controlled Origins in Backend FastAPI App

- **Severity:** High
- **CVSS 4.0:** 7.6
- **CWE:** CWE-942
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/app.py:133`
- **Source:** Workspace × CWE-942
- **QA Status:** Confirmed

### 13. Missing Authorization (IDOR) in Image, Text, and Engine Endpoints via Existence-Only Validators

- **Severity:** High
- **CVSS 4.0:** 7.6
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Location:** `db_service/utils.py:59`
- **Source:** Systemic: Existence-only validators (`is_valid_*_ids`, `validate_references`) misused as authorization across image/text/engine endpoints × CWE-863
- **QA Status:** Confirmed

### 14. Cleartext Transmission of OAuth Credentials and Auth Tokens in Backend Services

- **Severity:** High
- **CVSS 4.0:** 7.4
- **CWE:** CWE-319
- **Vector:** `CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/inner_requests.py:56`
- **Source:** Workspace × CWE-319
- **QA Status:** Confirmed

### 15. Missing Authorization on org_id in POST /billing/internal/consume

- **Severity:** High
- **CVSS 4.0:** 7.2
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Location:** `backend/billing_service/billing_app.py:216`
- **Source:** Global::api_consume_usage(Request, ConsumeUsageRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 16. Path Traversal via Unsanitized `request-id` Header in Image Upload and Generation Endpoints

- **Severity:** High
- **CVSS 4.0:** 7.2
- **CWE:** CWE-22
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Location:** `backend/inner_requests.py:58`
- **Source:** Systemic: Unsanitized 'request-id' HTTP header interpolated into filesystem write paths across services × CWE-22
- **QA Status:** Confirmed

### 17. Missing Image-Ownership Authorization in `update_image_permission` Endpoint

- **Severity:** High
- **CVSS 4.0:** 7.2
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:L/SI:L/SA:N`
- **Location:** `backend/permission_service/permission_app.py:27`
- **Source:** Global::update_image_permission(UpdateImagePermissionRequest, Request, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 18. Missing Authorization in `/update_human_eval` Moderation Endpoint

- **Severity:** High
- **CVSS 4.0:** 7.1
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Location:** `image_register_project/app.py:114`
- **Source:** Global::update_human_eval(UpdateHumanEvalRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 19. Missing Brute-Force Protection on Authentication Endpoints

- **Severity:** Medium
- **CVSS 4.0:** 9.1
- **CWE:** CWE-307
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/user_service/user_app.py:718`
- **Source:** Workspace × CWE-307
- **QA Status:** Confirmed

### 20. Missing Authorization on Rating Queue Endpoints in image_caption_app.py

- **Severity:** Medium
- **CVSS 4.0:** 8.8
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Location:** `search_project/image_caption_app.py:224`
- **Source:** Systemic: `image_caption_app.py` unauthenticated rating queue endpoints × CWE-863
- **QA Status:** Confirmed

### 21. Missing Authentication on Form Branch of `POST /device/consent`

- **Severity:** Medium
- **CVSS 4.0:** 8.2
- **CWE:** CWE-306
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:L/SI:L/SA:N`
- **Location:** `backend/oauth_service/oauth_login.py:994`
- **Source:** Global::device_consent_submit(Request) -> Response × CWE-306
- **QA Status:** Confirmed

### 22. Missing Authorization on Canvas Project Read Endpoints

- **Severity:** Medium
- **CVSS 4.0:** 7.1
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/canvas_service/canvas_app.py:58`
- **Source:** Systemic: Canvas service project/operation endpoints missing `resolve_effective_permission` check × CWE-863
- **QA Status:** Confirmed

### 23. Missing Authorization on Canvas WebSocket Stats Endpoint

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/canvas_service/canvas_app.py:543`
- **Source:** Global::get_canvas_websocket_stats() -> Response × CWE-863
- **QA Status:** Confirmed

### 24. Missing Authentication in POST /get_user_details Enables User Enumeration and PII Disclosure

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-306
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/getinfo_service/getinfo_app.py:358`
- **Source:** Global::get_user_details(Request, GetUserDetailsRequest, Optional[str]) -> Response × CWE-306
- **QA Status:** Confirmed

### 25. Missing Authentication on `/recall_by_image` Enables Resource-Exhaustion DoS

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-306
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`
- **Location:** `search_project/image_search_app.py:77`
- **Source:** Global::recall_by_text_and_image_list() -> Response × CWE-306
- **QA Status:** Confirmed

### 26. Unauthenticated Server-Side Request Forgery via /register_multiple_images URL Queue

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-918
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`
- **Location:** `image_register_project/app.py:187`
- **Source:** Global::register_multiple_images(List[str]) -> List[ImageUrlResponse] × CWE-918
- **QA Status:** Confirmed

### 27. Path Traversal in search_project Image Path Handling

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-22
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N`
- **Location:** `search_project/image_utils.py:97`
- **Source:** Systemic: search_project endpoints pass user-controlled image paths to PIL.Image.open without directory containment × CWE-22
- **QA Status:** Confirmed

### 28. Server-Side Request Forgery in `/recall_by_image` Endpoint

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-918
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L`
- **Location:** `search_project/image_search_app.py:77`
- **Source:** Global::recall_by_text_and_image_list() -> Response × CWE-918
- **QA Status:** Confirmed

### 29. Missing Authentication on State-Changing Endpoints in image_register_project

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`
- **Location:** `image_register_project/app.py:150`
- **Source:** Systemic: `image_register_project` unauthenticated write/enqueue endpoints × CWE-863
- **QA Status:** Confirmed

### 30. Missing Authorization in Project WebSocket Endpoint

- **Severity:** Medium
- **CVSS 4.0:** 6.9
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/websocket_app.py:19`
- **Source:** Global::websocket_endpoint(WebSocket, str, Request) -> void × CWE-863
- **QA Status:** Confirmed

### 31. Authentication Tokens Logged via Full Request Headers in Token Verification Helpers

- **Severity:** Medium
- **CVSS 4.0:** 6.8
- **CWE:** CWE-532
- **Vector:** `CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N`
- **Location:** `backend/user_service/user_app.py:132`
- **Source:** Workspace × CWE-532
- **QA Status:** Confirmed

### 32. Server-Side Request Forgery in get_response_from_url Helper

- **Severity:** Medium
- **CVSS 4.0:** 6.3
- **CWE:** CWE-918
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N`
- **Location:** `image_project/image_generator/utils/__init__.py:92, lamm_project/engine.py:19`
- **Source:** Systemic: image_project endpoints fetch attacker-controlled URLs via unvalidated get_image_from_url helper × CWE-918
- **QA Status:** Confirmed

### 33. Missing Authorization in update_style_permission Endpoint

- **Severity:** Medium
- **CVSS 4.0:** 6.1
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N`
- **Location:** `backend/permission_service/permission_app.py:630`
- **Source:** Global::update_style_permission(UpdateStylePermissionRequest, Request, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 34. Missing Authorization in `delete_workflow_template` Endpoint

- **Severity:** Medium
- **CVSS 4.0:** 6.1
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Location:** `backend/create_service/create_app.py:237`
- **Source:** Global::delete_workflow_template_endpoint(Request, DeleteWorkflowTemplateRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 35. Owner Authorization Bypass in Stripe `_require_org_owner` Default-Org Path

- **Severity:** Medium
- **CVSS 4.0:** 6.1
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:H/SC:N/SI:L/SA:L`
- **Location:** `backend/stripe_service/stripe_engine.py:80`
- **Source:** Systemic: Stripe `_require_org_owner` owner-check bypass in default-org path × CWE-863
- **QA Status:** Confirmed

### 36. Missing Per-Caller Authorization (IDOR) Across Getinfo Service Read Endpoints

- **Severity:** Medium
- **CVSS 4.0:** 6.0
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/getinfo_service/getinfo_app.py:22`
- **Source:** Systemic: Getinfo service endpoints leak resources by ID without per-caller authorization × CWE-863
- **QA Status:** Confirmed

### 37. Missing Space-Level Authorization in verify_invite_user Endpoint Enables User and Membership Enumeration

- **Severity:** Medium
- **CVSS 4.0:** 5.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/permission_service/permission_app.py:402`
- **Source:** Global::verify_invite_user_endpoint(VerifyInviteUserRequest, Request, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 38. Missing Authorization on Organization Update Path in `create_organization_endpoint`

- **Severity:** Medium
- **CVSS 4.0:** 5.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/create_service/create_app.py:79`
- **Source:** Global::create_organization_endpoint(Request, CreateOrganizationRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 39. Server-Side Request Forgery in /recall_images Image Fetch

- **Severity:** Medium
- **CVSS 4.0:** 5.3
- **CWE:** CWE-918
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N`
- **Location:** `search_project/app.py:79`
- **Source:** Global::recall_images_endpoint(RecallImagesRequest, Request) -> Response × CWE-918
- **QA Status:** Confirmed

### 40. Missing Authorization in `/get_pending_images` Moderation Queue Endpoint

- **Severity:** Medium
- **CVSS 4.0:** 5.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `image_register_project/app.py:73`
- **Source:** Global::get_pending_images(GetPendingImagesRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 41. Server-Side Request Forgery via Unvalidated `reference_image_urls` in `/enhance_query_with_references`

- **Severity:** Medium
- **CVSS 4.0:** 5.1
- **CWE:** CWE-918
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:N/VA:L/SC:L/SI:N/SA:N`
- **Location:** `agent_project/app.py:106`
- **Source:** Global::enhance_query_endpoint(EnhanceQueryRequest, Request) -> Response × CWE-918
- **QA Status:** Confirmed

### 42. Server-Side Request Forgery in /compute_aesthetic_summary Image URL Handler

- **Severity:** Medium
- **CVSS 4.0:** 5.1
- **CWE:** CWE-918
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N`
- **Location:** `lamm_project/app.py:36`
- **Source:** Global::compute_aesthetic_summary_endpoint(ComputeAestheticSummaryRequest, Request) -> Response × CWE-918
- **QA Status:** Confirmed

### 43. Unrestricted File Upload in `/upload_images` Endpoint Allows HTML/SVG Hosting on Public GCS Bucket

- **Severity:** Medium
- **CVSS 4.0:** 4.8
- **CWE:** CWE-434
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`
- **Location:** `backend/app.py:212`
- **Source:** Global::upload_images_endpoint(Request, List[UploadFile], bool, Optional[str], Optional[str], str) -> Response × CWE-434
- **QA Status:** Confirmed

### 44. Missing Ownership Check in Style Update Path of create_style_endpoint

- **Severity:** Medium
- **CVSS 4.0:** 2.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/create_service/create_app.py:128`
- **Source:** Global::create_style_endpoint(Request, CreateStyleRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 45. Missing Cross-Tenant Authorization in `api_upload_image` Canvas-Placement Branch

- **Severity:** Medium
- **CVSS 4.0:** 2.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`
- **Location:** `mcp_project/app.py:275`
- **Source:** Global::api_upload_image(Request, UploadFile, str, str, float, float, float, float, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 46. Missing Authorization on WebSocket Stats Telemetry Endpoint

- **Severity:** Low
- **CVSS 4.0:** 6.9
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/websocket_app.py:161`
- **Source:** Global::websocket_stats() -> Response × CWE-863
- **QA Status:** Confirmed

### 47. Cleartext Storage of Secrets in Environment Variables

- **Severity:** Low
- **CVSS 4.0:** 5.7
- **CWE:** CWE-526
- **Vector:** `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:L`
- **Location:** `backend/stripe_service/stripe_config.py:13`
- **Source:** Workspace × CWE-526
- **QA Status:** Confirmed

### 48. Open Redirect in OAuth Callback Bridge Page

- **Severity:** Low
- **CVSS 4.0:** 5.3
- **CWE:** CWE-601
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`
- **Location:** `backend/oauth_service/oauth_login.py:383`
- **Source:** Global::callback_bridge_page(Request) -> HTMLResponse × CWE-601
- **QA Status:** Confirmed

### 49. DOM-based XSS via Unvalidated URL Scheme in OAuth Callback Bridge

- **Severity:** Low
- **CVSS 4.0:** 2.3
- **CWE:** CWE-79
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/oauth_service/oauth_login.py:383`
- **Source:** Global::callback_bridge_page(Request) -> HTMLResponse × CWE-79
- **QA Status:** Confirmed

### 50. Missing Authorization in create_workflow_template Endpoint

- **Severity:** Low
- **CVSS 4.0:** 2.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/create_service/create_app.py:192`
- **Source:** Global::create_workflow_template_endpoint(Request, CreateWorkflowTemplateRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 51. Missing Authorization in get_workflow_template Endpoint Allows Cross-User Template Disclosure

- **Severity:** Low
- **CVSS 4.0:** 2.3
- **CWE:** CWE-863
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`
- **Location:** `backend/create_service/create_app.py:279`
- **Source:** Global::get_workflow_template_endpoint(Request, GetWorkflowTemplateRequest, str) -> Response × CWE-863
- **QA Status:** Confirmed

### 52. Exposed SSRF Primitive via Unrestricted `upload_image` MCP Tool

- **Severity:** Low
- **CVSS 4.0:** 2.1
- **CWE:** CWE-749
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:N/SA:N`
- **Location:** `mcp_project/tools/image_tools.py:178`
- **Source:** Workspace × CWE-749
- **QA Status:** Confirmed

### 53. Missing Clickjacking Protections on OAuth Consent and Login Pages

- **Severity:** Low
- **CVSS 4.0:** 2.1
- **CWE:** CWE-1021
- **Vector:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`
- **Source:** Workspace × CWE-1021
- **QA Status:** Confirmed

## Appendix A: Deduplicated Findings

| Finding | Sev | Duplicate Of |
|---------|-----|-------------|
| Path Traversal via Unauthenticated Callback in backend_callback | Critical | #3: Path Traversal via Unauthenticated Callback in backend_callback |
| Hand-Rolled JWT Verifier with Hardcoded Secret and Timing-Unsafe HMAC Comparison | Critical | #7: Missing Authentication on `/image_project_callback` Endpoint |
| Incorrect Authorization via Hardcoded API Key in Credit-Grant Admin Endpoint | High | #1: Hard-coded Credentials Committed Across Repository (GCP Service Account, Internal Admin API Key, Third-Party API Keys) |
| Missing Authorization on `join_project` in Canvas WebSocket Handler | High | #16: Missing Authorization in `/get_user_details` Enables Unauthenticated PII and Invitation Code Disclosure |
| Missing Authorization on Canvas Pub/Sub Stats Endpoint Leaks Operational Metadata | Low | #12: Missing Authorization on `/image_project_callback` Allows Forged Asset Ownership |
| Missing Authentication and Authorization in Chat WebSocket Endpoint | Medium | #40: Missing Authorization in update_style_permission Endpoint |

## Appendix B: CWE Coverage

| CWE | Title | Count |
|-----|-------|-------|
| CWE-22 | Path Traversal | 2 |
| CWE-79 | XSS | 1 |
| CWE-306 | Missing Authentication | 5 |
| CWE-307 | Excessive Auth Attempts | 1 |
| CWE-310 | Cryptographic Issues | 1 |
| CWE-319 | Cleartext Transmission | 1 |
| CWE-434 | Unrestricted Upload | 1 |
| CWE-526 | Cleartext Storage in Env Var | 1 |
| CWE-532 | Sensitive Info in Log | 1 |
| CWE-601 | Open Redirect | 1 |
| CWE-749 | Exposed Dangerous Method | 1 |
| CWE-798 | Hard-coded Credentials | 1 |
| CWE-863 | Incorrect Authorization | 28 |
| CWE-918 | SSRF | 6 |
| CWE-942 | Permissive CORS | 1 |
| CWE-1021 | Clickjacking | 1 |
