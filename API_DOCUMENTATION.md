# C360 Compliance Management Platform - API Documentation

## Overview

The C360 API provides comprehensive endpoints for managing compliance frameworks, controls, evidence, assessments, tasks, and projects in a multi-tenant environment.

## Authentication

All API endpoints (except health checks) require authentication via session cookies. Use the `/auth/login` endpoint to authenticate and obtain a session.

## Base URL

- Development: `http://localhost:8787`
- Production: Configured via `NEXT_PUBLIC_API_BASE_URL`

## Headers

All POST requests require:
- `Content-Type: application/json`
- `x-csrf: 1` (CSRF protection)

## API Endpoints

### Authentication APIs

#### `POST /auth/signup`
Register a new user and organization.
```json
{
  "email": "user@company.com",
  "name": "John Doe",
  "company": "Acme Corp",
  "password": "securepassword",
  "tenant": "acme" // optional
}
```

#### `POST /auth/login`
Authenticate user.
```json
{
  "email": "user@company.com",
  "password": "securepassword",
  "totp": "123456" // required if MFA enabled
}
```

#### `GET /auth/me`
Get current user session information.

#### `POST /auth/logout`
Logout and clear session.

#### `POST /auth/mfa/setup`
Setup MFA/TOTP for current user.

### User Management APIs

#### `GET /users`
List users in current tenant.
- Query params: `limit` (max 100), `offset`

#### `GET /users/:id`
Get specific user details.

#### `PUT /users/:id`
Update user details.
```json
{
  "name": "Updated Name",
  "role": "compliance_manager", // company_admin, compliance_manager, team_member, auditor
  "status": "active" // active, inactive, pending
}
```

#### `POST /users/:id/deactivate`
Deactivate user account.

### Tenant Management APIs

#### `GET /tenant`
Get current tenant details and settings.

#### `PUT /tenant`
Update tenant settings.
```json
{
  "name": "Updated Company Name",
  "plan": "professional" // starter, professional, enterprise
}
```

#### `GET /tenant/users`
List users in current tenant (same as `/users`).

### Compliance Framework APIs

#### `GET /frameworks`
List all available compliance frameworks.

#### `GET /tenant/frameworks`
List frameworks enabled for current tenant.

#### `POST /frameworks/:id/enable`
Enable a framework for current tenant.

#### `POST /frameworks/:id/disable`
Disable a framework for current tenant.

### Control Management APIs

#### `GET /controls`
List controls for current tenant.
- Query params: `framework` (filter by framework), `limit`, `offset`

#### `POST /controls`
Create a new control.
```json
{
  "frameworkId": "soc2", // optional
  "code": "CC1.1",
  "title": "Control Environment",
  "description": "Detailed description",
  "controlType": "manual", // manual, automated, hybrid
  "frequency": "annual", // daily, weekly, monthly, quarterly, annual
  "ownerUserId": "user-uuid" // optional
}
```

#### `GET /controls/:id`
Get control details.

#### `PUT /controls/:id`
Update control.
```json
{
  "title": "Updated Title",
  "description": "Updated description",
  "status": "in_progress", // not_started, in_progress, under_review, completed, failed
  "ownerUserId": "user-uuid"
}
```

### Evidence Management APIs

#### `GET /evidence`
List evidence items for current tenant.
- Query params: `limit`, `offset`

#### `POST /evidence`
Create evidence item.
```json
{
  "name": "Security Policy Document",
  "description": "Company security policy",
  "fileUrl": "https://storage.example.com/policy.pdf",
  "fileType": "application/pdf",
  "fileSize": 1024000
}
```

#### `GET /evidence/:id`
Get evidence details.

#### `PUT /evidence/:id`
Update evidence item.

#### `POST /evidence/:id/attach`
Attach evidence to a control.
```json
{
  "controlId": "control-uuid"
}
```

#### `GET /controls/:id/evidence`
Get evidence attached to a control.

### Assessment APIs

#### `GET /assessments`
List assessments for current tenant.
- Query params: `control` (filter by control), `limit`, `offset`

#### `POST /assessments`
Create assessment.
```json
{
  "controlId": "control-uuid",
  "assessorUserId": "user-uuid", // optional
  "dueDate": "2024-12-31",
  "notes": "Assessment notes"
}
```

#### `GET /assessments/:id`
Get assessment details.

#### `PUT /assessments/:id`
Update assessment.
```json
{
  "status": "completed", // planned, in_progress, completed, failed
  "result": "pass", // pass, fail, na, partial
  "notes": "Assessment completed successfully",
  "assessmentDate": "2024-01-15"
}
```

### Task Management APIs

#### `GET /tasks`
List tasks for current tenant.
- Query params: `assigned_to`, `project`, `status`, `limit`, `offset`

#### `POST /tasks`
Create task.
```json
{
  "title": "Review security controls",
  "description": "Detailed task description",
  "projectId": "project-uuid", // optional
  "controlId": "control-uuid", // optional
  "assignedTo": "user-uuid", // optional
  "priority": "high", // low, medium, high, critical
  "dueDate": "2024-12-31"
}
```

#### `GET /tasks/:id`
Get task details.

#### `PUT /tasks/:id`
Update task.
```json
{
  "status": "completed", // open, in_progress, completed, cancelled
  "assignedTo": "user-uuid",
  "priority": "medium"
}
```

### Project Management APIs

#### `GET /projects`
List projects for current tenant.
- Query params: `limit`, `offset`

#### `POST /projects`
Create project.
```json
{
  "name": "SOC 2 Compliance Initiative",
  "description": "Prepare for SOC 2 audit",
  "managerUserId": "user-uuid", // optional
  "startDate": "2024-01-01",
  "endDate": "2024-12-31"
}
```

#### `GET /projects/:id`
Get project details.

#### `PUT /projects/:id`
Update project.
```json
{
  "status": "active", // active, completed, on_hold, cancelled
  "managerUserId": "user-uuid"
}
```

### Audit Log APIs

#### `GET /audit`
Get audit logs for current tenant.
- Query params: `limit`, `offset`

### Reporting APIs

#### `GET /reports/compliance`
Get compliance status report.
- Query params: `framework` (optional)

#### `GET /reports/tasks`
Get task summary report.
- Query params: `user` (optional)

### Utility APIs

#### `GET /health`
Health check endpoint.

#### `GET /branding`
Get tenant branding.
- Query params: `tenant` (required)

#### `PUT /branding`
Update tenant branding.
```json
{
  "logoText": "Company Name",
  "primary": "#0b62d6",
  "secondary": "#eef6ff"
}
```

## Response Format

All API responses follow this format:

### Success Response
```json
{
  "ok": true,
  "data": { ... }
}
```

### Error Response
```json
{
  "error": "error_code",
  "message": "Human readable error message"
}
```

## Error Codes

- `unauthorized` - Authentication required
- `tenant_not_found` - Tenant not found
- `invalid_credentials` - Invalid login credentials
- `csrf_required` - CSRF token required
- `invalid_body` - Invalid request body
- `not_found` - Resource not found
- `invalid_*` - Validation errors for specific fields

## Available Compliance Frameworks

- `soc2` - SOC 2 (System and Organization Controls Type 2)
- `iso27001` - ISO 27001 (Information Security Management)
- `gdpr` - GDPR (General Data Protection Regulation)
- `pci-dss` - PCI DSS (Payment Card Industry Data Security Standard)
- `hipaa` - HIPAA (Health Insurance Portability and Accountability Act)
- `sox` - SOX (Sarbanes-Oxley Act)
- `nist-csf` - NIST Cybersecurity Framework
- `iso27002` - ISO 27002 (Code of practice for information security controls)

## User Roles

- `company_admin` - Full administrative access
- `compliance_manager` - Manage compliance activities
- `team_member` - Basic access to assigned tasks
- `auditor` - Read-only access for auditing purposes