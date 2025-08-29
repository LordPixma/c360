"use client";

interface QuickActionsProps {
  brand: {
    primary: string;
  };
}

export function QuickActions({ brand }: QuickActionsProps) {
  const actions = [
    {
      title: 'Upload Evidence',
      description: 'Drag & drop files or browse',
      icon: '📎',
      color: '#22c55e',
      action: () => console.log('Upload evidence')
    },
    {
      title: 'Request Extension',
      description: 'Need more time for a task?',
      icon: '⏰',
      color: '#f59e0b',
      action: () => console.log('Request extension')
    },
    {
      title: 'Ask for Help',
      description: 'Connect with compliance team',
      icon: '💬',
      color: '#3b82f6',
      action: () => console.log('Ask for help')
    },
    {
      title: 'View Instructions',
      description: 'Get detailed guidance',
      icon: '📖',
      color: '#8b5cf6',
      action: () => console.log('View instructions')
    }
  ];

  const suggestions = [
    'Complete your security awareness training by Friday',
    'Review the new GDPR compliance checklist',
    'Schedule your quarterly compliance review'
  ];

  return (
    <div style={{ 
      background: '#fff', 
      borderRadius: '12px', 
      padding: '24px',
      boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
      border: '1px solid #f1f5f9',
      marginBottom: '32px'
    }}>
      <h2 style={{ 
        margin: 0, 
        marginBottom: '20px', 
        fontSize: '20px', 
        fontWeight: 600,
        color: '#1e293b',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        ⚡ Quick Actions
      </h2>
      
      {/* Action Buttons */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
        gap: '16px',
        marginBottom: '24px'
      }}>
        {actions.map((action, index) => (
          <button
            key={index}
            onClick={action.action}
            style={{
              background: '#fff',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '16px',
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'all 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '12px'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = action.color;
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = '#e2e8f0';
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <div style={{
              width: '40px',
              height: '40px',
              background: `${action.color}15`,
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px'
            }}>
              {action.icon}
            </div>
            <div>
              <h3 style={{ 
                margin: 0, 
                fontSize: '16px', 
                fontWeight: 600,
                color: '#1e293b',
                marginBottom: '4px'
              }}>
                {action.title}
              </h3>
              <p style={{ 
                margin: 0, 
                fontSize: '14px', 
                color: '#64748b'
              }}>
                {action.description}
              </p>
            </div>
          </button>
        ))}
      </div>

      {/* Smart Suggestions */}
      <div style={{
        background: '#f8fafc',
        borderRadius: '8px',
        padding: '16px',
        border: '1px solid #e2e8f0'
      }}>
        <h3 style={{ 
          margin: 0, 
          marginBottom: '12px', 
          fontSize: '16px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          💡 Smart Suggestions
        </h3>
        <p style={{ 
          margin: 0, 
          marginBottom: '12px', 
          fontSize: '14px', 
          color: '#64748b'
        }}>
          Based on your role and current tasks:
        </p>
        <ul style={{ 
          margin: 0, 
          paddingLeft: '16px',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px'
        }}>
          {suggestions.map((suggestion, index) => (
            <li key={index} style={{ 
              fontSize: '14px', 
              color: '#475569',
              lineHeight: 1.5
            }}>
              {suggestion}
            </li>
          ))}
        </ul>
      </div>

      {/* File Drop Zone */}
      <div style={{
        marginTop: '16px',
        border: '2px dashed #cbd5e1',
        borderRadius: '8px',
        padding: '24px',
        textAlign: 'center',
        background: '#f8fafc',
        transition: 'all 0.2s ease'
      }}
      onDragOver={(e) => {
        e.preventDefault();
        e.currentTarget.style.borderColor = brand.primary;
        e.currentTarget.style.background = `${brand.primary}05`;
      }}
      onDragLeave={(e) => {
        e.currentTarget.style.borderColor = '#cbd5e1';
        e.currentTarget.style.background = '#f8fafc';
      }}>
        <div style={{ fontSize: '32px', marginBottom: '8px' }}>📁</div>
        <p style={{ 
          margin: 0, 
          fontSize: '16px', 
          fontWeight: 600,
          color: '#1e293b',
          marginBottom: '4px'
        }}>
          Drop files here to upload evidence
        </p>
        <p style={{ 
          margin: 0, 
          fontSize: '14px', 
          color: '#64748b'
        }}>
          Or click to browse • Supports PDF, DOC, images up to 10MB
        </p>
      </div>
    </div>
  );
}