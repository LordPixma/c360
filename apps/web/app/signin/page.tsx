import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../../lib/tenant';
import { getBranding } from '../actions/getBranding';
import { SignInForm } from '../../components/SignInForm';

export default async function SignInPage() {
  const hdrs = headers();
  const hostname = parseHost(hdrs.get('host'));
  const { tenant } = tenantFromHost(hostname);
  const brand = await getBranding(tenant);
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

  const containerStyle = {
    minHeight: '100vh',
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans", "Helvetica Neue", sans-serif',
  };

  const leftPanelStyle = {
    background: `linear-gradient(135deg, ${brand.primary}, ${brand.primary}dd)`,
    color: 'white',
    padding: '60px 40px',
    display: 'flex',
    flexDirection: 'column' as const,
    justifyContent: 'center',
    position: 'relative' as const,
    overflow: 'hidden',
  };

  const rightPanelStyle = {
    backgroundColor: 'white',
    padding: '60px 40px',
    display: 'flex',
    flexDirection: 'column' as const,
    justifyContent: 'center',
    alignItems: 'center',
  };

  return (
    <>
      <style dangerouslySetInnerHTML={{
        __html: `
          @media (max-width: 768px) {
            .signin-container {
              grid-template-columns: 1fr !important;
              grid-template-rows: auto 1fr !important;
            }
            
            .left-panel {
              padding: 40px 20px !important;
              text-align: center;
            }
            
            .right-panel {
              padding: 40px 20px !important;
            }
          }
          
          @media (max-width: 480px) {
            .left-panel {
              padding: 30px 15px !important;
            }
            
            .right-panel {
              padding: 30px 15px !important;
            }
          }
        `
      }} />
      
      <div className="signin-container" style={containerStyle}>
        {/* Left Panel - Branding */}
        <div className="left-panel" style={leftPanelStyle}>
          <div style={{ position: 'relative', zIndex: 1 }}>
            <div style={{ marginBottom: '40px' }}>
              <h1 style={{ 
                fontSize: '2.5rem', 
                fontWeight: '700', 
                marginBottom: '16px',
                letterSpacing: '-0.025em',
                margin: '0 0 16px 0'
              }}>
                {brand.logoText}
              </h1>
              <div style={{
                width: '60px',
                height: '4px',
                backgroundColor: 'rgba(255, 255, 255, 0.6)',
                borderRadius: '2px'
              }} />
            </div>
            
            <div style={{ marginBottom: '40px' }}>
              <h2 style={{ 
                fontSize: '1.75rem', 
                fontWeight: '600', 
                marginBottom: '20px',
                lineHeight: '1.3',
                margin: '0 0 20px 0'
              }}>
                Comprehensive Compliance Management
              </h2>
              <p style={{ 
                fontSize: '1.125rem', 
                opacity: 0.9, 
                lineHeight: '1.6',
                marginBottom: '24px',
                margin: '0 0 24px 0'
              }}>
                Streamline your compliance processes with our multi-tenant platform designed for modern organizations.
              </p>
            </div>
            
            <div style={{ 
              display: 'flex', 
              flexDirection: 'column', 
              gap: '16px',
              fontSize: '0.95rem',
              opacity: 0.8
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ 
                  width: '8px', 
                  height: '8px', 
                  backgroundColor: 'rgba(255, 255, 255, 0.7)', 
                  borderRadius: '50%',
                  flexShrink: 0
                }} />
                <span>SOC 2, ISO 27001, GDPR, and more</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ 
                  width: '8px', 
                  height: '8px', 
                  backgroundColor: 'rgba(255, 255, 255, 0.7)', 
                  borderRadius: '50%',
                  flexShrink: 0
                }} />
                <span>Automated workflows and evidence collection</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ 
                  width: '8px', 
                  height: '8px', 
                  backgroundColor: 'rgba(255, 255, 255, 0.7)', 
                  borderRadius: '50%',
                  flexShrink: 0
                }} />
                <span>Enterprise-grade security and audit trails</span>
              </div>
            </div>
          </div>
        </div>
        
        {/* Right Panel - Form */}
        <div className="right-panel" style={rightPanelStyle}>
          <div style={{ width: '100%', maxWidth: '400px' }}>
            <div style={{ marginBottom: '40px', textAlign: 'center' }}>
              <h2 style={{ 
                fontSize: '1.875rem', 
                fontWeight: '700', 
                color: '#111827',
                marginBottom: '8px',
                margin: '0 0 8px 0'
              }}>
                Welcome back
              </h2>
              <p style={{ 
                fontSize: '1rem', 
                color: '#6b7280',
                margin: 0
              }}>
                Sign in to your account to continue
              </p>
            </div>
            
            <SignInForm siteKey={siteKey} />
            
            <div style={{ 
              marginTop: '32px', 
              paddingTop: '24px', 
              borderTop: '1px solid #f3f4f6',
              textAlign: 'center'
            }}>
              <p style={{ fontSize: '0.875rem', color: '#6b7280', margin: 0 }}>
                Don't have an account?{' '}
                <a 
                  href="/signup" 
                  style={{ 
                    color: brand.primary, 
                    textDecoration: 'none',
                    fontWeight: '500'
                  }}
                >
                  Create account
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
