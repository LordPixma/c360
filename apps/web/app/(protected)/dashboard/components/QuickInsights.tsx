"use client";

interface QuickInsightsProps {
  brand: {
    primary: string;
  };
}

export function QuickInsights({ brand }: QuickInsightsProps) {
  // Mock data
  const learningData = {
    nextTraining: {
      title: 'Security Awareness Training',
      date: '2024-02-15',
      duration: '45 minutes',
      provider: 'CyberSafe Academy'
    },
    recentCompletions: [
      { course: 'GDPR Fundamentals', date: '2024-01-20', certificate: true },
      { course: 'Incident Response', date: '2024-01-10', certificate: true }
    ],
    timeInvested: '12.5 hours this month',
    streakDays: 5
  };

  const evidenceData = {
    recentUploads: [
      { name: 'Security_Policy_2024.pdf', date: '2 hours ago', type: 'pdf' },
      { name: 'Access_Control_Matrix.xlsx', date: '1 day ago', type: 'excel' },
      { name: 'Training_Certificate.jpg', date: '3 days ago', type: 'image' }
    ],
    pendingRequests: 3,
    storageUsed: 68,
    totalStorage: 100
  };

  const collaborationData = {
    recentComments: [
      { from: 'Sarah Chen', task: 'Risk Assessment Review', time: '2 hours ago' },
      { from: 'Mike Rodriguez', task: 'Vendor Assessment', time: '1 day ago' }
    ],
    pendingReviews: 2,
    sharedDocuments: 8,
    teamMentions: 4
  };

  const getFileIcon = (type: string) => {
    switch (type) {
      case 'pdf': return '📄';
      case 'excel': return '📊';
      case 'image': return '🖼️';
      case 'word': return '📝';
      default: return '📎';
    }
  };

  return (
    <div className="insights-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '24px' }}>
      {/* Learning & Development */}
      <div style={{ 
        background: '#fff', 
        borderRadius: '12px', 
        padding: '24px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
        border: '1px solid #f1f5f9'
      }}>
        <h2 style={{ 
          margin: 0, 
          marginBottom: '20px', 
          fontSize: '18px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          🎓 Learning & Development
        </h2>
        
        {/* Next Training */}
        <div style={{
          background: '#fefce8',
          border: '1px solid #fde047',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '16px'
        }}>
          <h3 style={{ 
            margin: 0, 
            fontSize: '16px', 
            fontWeight: 600,
            color: '#1e293b',
            marginBottom: '8px'
          }}>
            📅 Next Required Training
          </h3>
          <p style={{ 
            margin: 0, 
            fontSize: '14px', 
            fontWeight: 600,
            color: '#1e293b',
            marginBottom: '4px'
          }}>
            {learningData.nextTraining.title}
          </p>
          <p style={{ 
            margin: 0, 
            fontSize: '12px', 
            color: '#64748b',
            marginBottom: '8px'
          }}>
            {new Date(learningData.nextTraining.date).toLocaleDateString()} • {learningData.nextTraining.duration}
          </p>
          <button style={{
            background: brand.primary,
            color: '#fff',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '12px',
            cursor: 'pointer',
            fontWeight: 500
          }}>
            Schedule Now
          </button>
        </div>

        {/* Recent Completions */}
        <div style={{ marginBottom: '16px' }}>
          <h3 style={{ 
            margin: 0, 
            fontSize: '14px', 
            fontWeight: 600,
            color: '#1e293b',
            marginBottom: '12px'
          }}>
            Recent Completions
          </h3>
          {learningData.recentCompletions.map((completion, index) => (
            <div key={index} style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '8px 0',
              borderBottom: index < learningData.recentCompletions.length - 1 ? '1px solid #f1f5f9' : 'none'
            }}>
              <div>
                <p style={{ margin: 0, fontSize: '14px', fontWeight: 500, color: '#1e293b' }}>
                  {completion.course}
                </p>
                <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
                  {new Date(completion.date).toLocaleDateString()}
                </p>
              </div>
              {completion.certificate && (
                <span style={{ fontSize: '16px' }}>🏆</span>
              )}
            </div>
          ))}
        </div>

        {/* Stats */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: '1fr 1fr', 
          gap: '12px',
          marginTop: '16px'
        }}>
          <div style={{
            background: '#f8fafc',
            padding: '12px',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <p style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: brand.primary }}>
              {learningData.timeInvested}
            </p>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
              Time invested
            </p>
          </div>
          <div style={{
            background: '#f8fafc',
            padding: '12px',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <p style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#22c55e' }}>
              {learningData.streakDays} days
            </p>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
              Learning streak 🔥
            </p>
          </div>
        </div>
      </div>

      {/* Evidence Management */}
      <div style={{ 
        background: '#fff', 
        borderRadius: '12px', 
        padding: '24px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
        border: '1px solid #f1f5f9'
      }}>
        <h2 style={{ 
          margin: 0, 
          marginBottom: '20px', 
          fontSize: '18px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          📁 Evidence Management
        </h2>

        {/* Recent Uploads */}
        <div style={{ marginBottom: '20px' }}>
          <h3 style={{ 
            margin: 0, 
            fontSize: '14px', 
            fontWeight: 600,
            color: '#1e293b',
            marginBottom: '12px'
          }}>
            Recent Uploads
          </h3>
          {evidenceData.recentUploads.map((upload, index) => (
            <div key={index} style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '8px 0',
              borderBottom: index < evidenceData.recentUploads.length - 1 ? '1px solid #f1f5f9' : 'none'
            }}>
              <span style={{ fontSize: '20px' }}>{getFileIcon(upload.type)}</span>
              <div style={{ flex: 1 }}>
                <p style={{ 
                  margin: 0, 
                  fontSize: '14px', 
                  fontWeight: 500, 
                  color: '#1e293b',
                  marginBottom: '2px'
                }}>
                  {upload.name}
                </p>
                <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
                  {upload.date}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Storage Usage */}
        <div style={{
          background: '#f8fafc',
          padding: '16px',
          borderRadius: '8px',
          marginBottom: '16px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: '#1e293b' }}>
              Storage Used
            </span>
            <span style={{ fontSize: '14px', color: '#64748b' }}>
              {evidenceData.storageUsed}% of {evidenceData.totalStorage}GB
            </span>
          </div>
          <div style={{
            width: '100%',
            height: '8px',
            background: '#e2e8f0',
            borderRadius: '4px'
          }}>
            <div style={{
              width: `${evidenceData.storageUsed}%`,
              height: '100%',
              background: evidenceData.storageUsed > 80 ? '#f59e0b' : '#22c55e',
              borderRadius: '4px',
              transition: 'width 0.3s ease'
            }} />
          </div>
        </div>

        {/* Quick Actions */}
        <div style={{ display: 'flex', gap: '8px' }}>
          <button style={{
            flex: 1,
            background: brand.primary,
            color: '#fff',
            border: 'none',
            padding: '8px 12px',
            borderRadius: '6px',
            fontSize: '12px',
            cursor: 'pointer',
            fontWeight: 500
          }}>
            Quick Upload
          </button>
          <button style={{
            background: 'none',
            border: `1px solid ${brand.primary}`,
            color: brand.primary,
            padding: '8px 12px',
            borderRadius: '6px',
            fontSize: '12px',
            cursor: 'pointer',
            fontWeight: 500
          }}>
            View All ({evidenceData.pendingRequests})
          </button>
        </div>
      </div>

      {/* Collaboration */}
      <div style={{ 
        background: '#fff', 
        borderRadius: '12px', 
        padding: '24px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
        border: '1px solid #f1f5f9'
      }}>
        <h2 style={{ 
          margin: 0, 
          marginBottom: '20px', 
          fontSize: '18px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          🤝 Collaboration
        </h2>

        {/* Recent Comments */}
        <div style={{ marginBottom: '20px' }}>
          <h3 style={{ 
            margin: 0, 
            fontSize: '14px', 
            fontWeight: 600,
            color: '#1e293b',
            marginBottom: '12px'
          }}>
            Recent Activity
          </h3>
          {collaborationData.recentComments.map((comment, index) => (
            <div key={index} style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
              padding: '8px 0',
              borderBottom: index < collaborationData.recentComments.length - 1 ? '1px solid #f1f5f9' : 'none'
            }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '50%',
                background: brand.primary,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#fff',
                fontSize: '12px',
                fontWeight: 600,
                flexShrink: 0
              }}>
                {comment.from.split(' ').map(n => n[0]).join('')}
              </div>
              <div style={{ flex: 1 }}>
                <p style={{ 
                  margin: 0, 
                  fontSize: '14px', 
                  color: '#1e293b',
                  marginBottom: '2px'
                }}>
                  <strong>{comment.from}</strong> commented on <em>{comment.task}</em>
                </p>
                <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
                  {comment.time}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Quick Stats */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(2, 1fr)', 
          gap: '12px',
          marginBottom: '16px'
        }}>
          <div style={{
            background: '#f8fafc',
            padding: '12px',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <p style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#f59e0b' }}>
              {collaborationData.pendingReviews}
            </p>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
              Pending reviews
            </p>
          </div>
          <div style={{
            background: '#f8fafc',
            padding: '12px',
            borderRadius: '6px',
            textAlign: 'center'
          }}>
            <p style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: brand.primary }}>
              {collaborationData.sharedDocuments}
            </p>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>
              Shared docs
            </p>
          </div>
        </div>

        {/* Notifications */}
        {collaborationData.teamMentions > 0 && (
          <div style={{
            background: '#eff6ff',
            border: '1px solid #bfdbfe',
            borderRadius: '6px',
            padding: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <span style={{ fontSize: '16px' }}>💬</span>
            <p style={{ margin: 0, fontSize: '14px', color: '#1e40af' }}>
              You have <strong>{collaborationData.teamMentions} new mentions</strong> from your team
            </p>
          </div>
        )}
      </div>
    </div>
  );
}