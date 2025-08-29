# Microsoft 365 Tenant Integration

This guide explains how to integrate Comp360Flow with Microsoft 365 tenants to enable Single Sign-On (SSO) and automatic user provisioning.

## Overview

The M365 integration allows customers to:
- Sign in using their Microsoft 365 credentials
- Automatically provision users from their M365 tenant
- Maintain strict tenant isolation while leveraging existing identity infrastructure
- Verify user domain ownership through M365 tenant validation

## Prerequisites

1. **Azure App Registration**: You need to register an application in Azure AD/Entra ID
2. **Admin Access**: You need admin access to both the Comp360Flow tenant and the M365 tenant
3. **Domain Verification**: The M365 tenant must have verified domain ownership

## Setup Process

### 1. Azure App Registration

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Click "New registration"
3. Configure:
   - **Name**: "Comp360Flow Integration"
   - **Supported account types**: "Accounts in any organizational directory"
   - **Redirect URI**: `https://your-comp360flow-domain.com/auth/m365/callback`
4. Note the **Application (client) ID**
5. Go to "Certificates & secrets" > Create a new client secret
6. Note the **Client secret value**

### 2. API Permissions

Add the following Microsoft Graph permissions:
- `User.Read` (Delegated) - Read user profile
- `openid` (Delegated) - OpenID Connect sign-in
- `profile` (Delegated) - View user's basic profile
- `email` (Delegated) - View user's email address

### 3. Environment Configuration

Set the following environment variables in your Cloudflare Worker:

```bash
wrangler secret put M365_CLIENT_ID
wrangler secret put M365_CLIENT_SECRET
wrangler secret put M365_REDIRECT_URI
```

Or in your `wrangler.toml`:
```toml
[vars]
M365_CLIENT_ID = "your-app-client-id"
M365_CLIENT_SECRET = "your-app-client-secret"
M365_REDIRECT_URI = "https://your-domain.com/auth/m365/callback"
```

### 4. Database Migration

Run the M365 integration migration:
```bash
wrangler d1 execute <your-database> --file=./infra/migrations/0003_m365_integration.sql
```

### 5. Configure Tenant Mapping

Use the admin API to configure the M365 tenant mapping:

```bash
curl -X POST https://api.your-domain.com/admin/m365/configure \
  -H "Content-Type: application/json" \
  -d '{
    "tenantSlug": "customer-tenant",
    "m365TenantId": "customer-m365-tenant-id",
    "m365TenantDomain": "customer.onmicrosoft.com",
    "oauthEnabled": true,
    "autoProvision": true
  }'
```

## API Endpoints

### Authentication Flow

1. **GET `/auth/m365/authorize?tenant=<tenant-slug>`**
   - Returns the M365 authorization URL and state parameter
   - Client should redirect user to the authorization URL

2. **POST `/auth/m365/callback`**
   - Handles the OAuth callback with authorization code
   - Body: `{ "code": "auth-code", "state": "state-from-step-1" }`
   - Returns session cookie on success

### Configuration Management

3. **POST `/admin/m365/configure`**
   - Configure M365 tenant mapping
   - Requires admin access

4. **GET `/admin/m365/status?tenant=<tenant-slug>`**
   - Check M365 integration status for a tenant

## Security Considerations

- **Tenant Isolation**: Each Comp360Flow tenant can only be mapped to one M365 tenant
- **Domain Verification**: User emails must belong to the configured M365 tenant domain
- **Token Security**: Access tokens are not stored; only used for initial user verification
- **Auto-provisioning**: Can be disabled to require manual user creation

## Troubleshooting

### Common Issues

1. **"M365 tenant mismatch"**: User belongs to different M365 tenant than configured
2. **"OAuth exchange failed"**: Check client ID/secret configuration
3. **"M365 integration not configured"**: Run the tenant mapping configuration

### Debug Information

Check the M365 integration status:
```bash
curl "https://api.your-domain.com/admin/m365/status?tenant=customer-tenant"
```

Response includes:
- `configured`: Whether M365 mapping exists
- `mapping`: Current M365 tenant configuration  
- `oauthAvailable`: Whether OAuth environment variables are set

## Migration from Email/Password

Existing users with email/password can be automatically linked to M365 accounts when:
1. Email addresses match
2. User performs M365 sign-in
3. Auto-provisioning is enabled

No data migration is required - the system maintains both authentication methods.