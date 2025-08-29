"use client";

interface ProgressVisualizationProps {
  brand: {
    primary: string;
  };
}

export function ProgressVisualization({ brand }: ProgressVisualizationProps) {
  // Mock data
  const complianceJourney = [
    { 
      framework: 'SOC 2', 
      status: 'completed', 
      progress: 100, 
      dueDate: '2024-01-15',
      achievement: 'SOC 2 Type II Certified'
    },
    { 
      framework: 'ISO 27001', 
      status: 'in-progress', 
      progress: 75, 
      dueDate: '2024-03-30',
      currentStep: 'Risk Assessment Review'
    },
    { 
      framework: 'GDPR', 
      status: 'upcoming', 
      progress: 25, 
      dueDate: '2024-06-15',
      currentStep: 'Initial Assessment'
    },
    { 
      framework: 'PCI DSS', 
      status: 'planned', 
      progress: 0, 
      dueDate: '2024-09-01',
      currentStep: 'Not Started'
    }
  ];

  const teamProgress = {
    department: 'Engineering',
    completion: 82,
    totalMembers: 12,
    completedMembers: 10,
    averageCompletion: 78
  };

  const achievements = [
    { title: 'Early Bird', description: 'Completed 5 tasks ahead of schedule', date: '2 days ago' },
    { title: 'Team Player', description: 'Helped 3 colleagues with their tasks', date: '1 week ago' },
    { title: 'Evidence Master', description: 'Submitted 10 high-quality evidence documents', date: '2 weeks ago' }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#22c55e';
      case 'in-progress': return '#3b82f6';
      case 'upcoming': return '#f59e0b';
      case 'planned': return '#94a3b8';
      default: return '#94a3b8';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return '✅';
      case 'in-progress': return '🔄';
      case 'upcoming': return '📅';
      case 'planned': return '📋';
      default: return '📋';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* My Compliance Journey */}
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
          fontSize: '20px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          🏆 My Compliance Journey
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {complianceJourney.map((item, index) => (
            <div key={index} style={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              padding: '16px',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              background: item.status === 'completed' ? '#f0fdf4' : '#fff'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '50%',
                background: getStatusColor(item.status),
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '16px',
                color: '#fff',
                fontWeight: 'bold'
              }}>
                {getStatusIcon(item.status)}
              </div>
              
              <div style={{ flex: 1 }}>
                <h3 style={{ 
                  margin: 0, 
                  fontSize: '16px', 
                  fontWeight: 600,
                  color: '#1e293b',
                  marginBottom: '4px'
                }}>
                  {item.framework}
                </h3>
                <p style={{ 
                  margin: 0, 
                  fontSize: '14px', 
                  color: '#64748b',
                  marginBottom: '8px'
                }}>
                  {item.achievement || item.currentStep}
                </p>
                
                {/* Progress bar */}
                <div style={{
                  width: '100%',
                  height: '6px',
                  background: '#f1f5f9',
                  borderRadius: '3px',
                  marginBottom: '4px'
                }}>
                  <div style={{
                    width: `${item.progress}%`,
                    height: '100%',
                    background: getStatusColor(item.status),
                    borderRadius: '3px',
                    transition: 'width 0.3s ease'
                  }} />
                </div>
                
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>
                    {item.progress}% complete
                  </span>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>
                    Due: {new Date(item.dueDate).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Team Context */}
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
          fontSize: '20px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          👥 Team Progress
        </h2>
        
        <div style={{
          background: '#f8fafc',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '16px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#1e293b' }}>
              {teamProgress.department} Department
            </h3>
            <span style={{ fontSize: '18px', fontWeight: 700, color: brand.primary }}>
              {teamProgress.completion}%
            </span>
          </div>
          
          <div style={{
            width: '100%',
            height: '8px',
            background: '#e2e8f0',
            borderRadius: '4px',
            marginBottom: '12px'
          }}>
            <div style={{
              width: `${teamProgress.completion}%`,
              height: '100%',
              background: brand.primary,
              borderRadius: '4px',
              transition: 'width 0.3s ease'
            }} />
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', fontSize: '14px', color: '#64748b' }}>
            <div>
              <strong style={{ color: '#1e293b' }}>{teamProgress.completedMembers}</strong> of {teamProgress.totalMembers} members completed
            </div>
            <div>
              Team average: <strong style={{ color: '#1e293b' }}>{teamProgress.averageCompletion}%</strong>
            </div>
          </div>
        </div>
        
        <div style={{
          padding: '12px',
          background: '#ecfdf5',
          border: '1px solid #bbf7d0',
          borderRadius: '6px',
          fontSize: '14px',
          color: '#166534'
        }}>
          🎉 Your team is performing above average! Keep up the great work.
        </div>
      </div>

      {/* Recent Achievements */}
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
          fontSize: '20px', 
          fontWeight: 600,
          color: '#1e293b',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          🏅 Recent Achievements
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {achievements.map((achievement, index) => (
            <div key={index} style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
              padding: '12px',
              background: '#f8fafc',
              borderRadius: '8px',
              border: '1px solid #e2e8f0'
            }}>
              <div style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: '#22c55e',
                marginTop: '6px',
                flexShrink: 0
              }} />
              <div style={{ flex: 1 }}>
                <h3 style={{ 
                  margin: 0, 
                  fontSize: '14px', 
                  fontWeight: 600,
                  color: '#1e293b',
                  marginBottom: '4px'
                }}>
                  {achievement.title}
                </h3>
                <p style={{ 
                  margin: 0, 
                  fontSize: '12px', 
                  color: '#64748b',
                  marginBottom: '4px'
                }}>
                  {achievement.description}
                </p>
                <span style={{ 
                  fontSize: '11px', 
                  color: '#94a3b8'
                }}>
                  {achievement.date}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}