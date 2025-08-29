"use client";

interface Task {
  id: string;
  title: string;
  framework: string;
  dueDate: Date;
  priority: 'urgent' | 'high' | 'medium' | 'low';
  estimatedTime: string;
  status: 'pending' | 'in-progress' | 'completed';
  description?: string;
}

interface TaskManagementProps {
  brand: {
    primary: string;
  };
}

export function TaskManagement({ brand }: TaskManagementProps) {
  // Mock data - would come from API
  const todayTasks: Task[] = [
    {
      id: '1',
      title: 'Review access control policies',
      framework: 'SOC 2',
      dueDate: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours from now
      priority: 'urgent',
      estimatedTime: '30 min',
      status: 'pending',
      description: 'Review and update access control policies for Q4 compliance'
    },
    {
      id: '2',
      title: 'Upload security training certificates',
      framework: 'ISO 27001',
      dueDate: new Date(Date.now() + 4 * 60 * 60 * 1000), // 4 hours from now
      priority: 'high',
      estimatedTime: '15 min',
      status: 'in-progress'
    },
    {
      id: '3',
      title: 'Complete incident response documentation',
      framework: 'SOC 2',
      dueDate: new Date(Date.now() + 6 * 60 * 60 * 1000), // 6 hours from now
      priority: 'medium',
      estimatedTime: '45 min',
      status: 'pending'
    }
  ];

  const weekTasks = [
    {
      framework: 'SOC 2',
      tasks: 8,
      completed: 5,
      items: [
        { title: 'Security awareness training', due: 'Tomorrow', status: 'pending' },
        { title: 'Vendor assessment review', due: 'Wednesday', status: 'pending' },
        { title: 'Backup testing documentation', due: 'Friday', status: 'pending' }
      ]
    },
    {
      framework: 'ISO 27001',
      tasks: 5,
      completed: 3,
      items: [
        { title: 'Risk assessment update', due: 'Thursday', status: 'pending' },
        { title: 'Asset inventory review', due: 'Friday', status: 'pending' }
      ]
    }
  ];

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'urgent': return '#ef4444';
      case 'high': return '#f59e0b';
      case 'medium': return '#3b82f6';
      default: return '#64748b';
    }
  };

  const formatTimeLeft = (dueDate: Date) => {
    const now = new Date();
    const diff = dueDate.getTime() - now.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    if (hours > 0) return `${hours}h ${minutes}m left`;
    if (minutes > 0) return `${minutes}m left`;
    return 'Overdue';
  };

  return (
    <div className="task-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
      {/* Today's Priorities */}
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
          🎯 Today's Priorities
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {todayTasks.map((task) => (
            <div
              key={task.id}
              style={{
                padding: '16px',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                borderLeft: `4px solid ${getPriorityColor(task.priority)}`,
                background: '#fff',
                transition: 'all 0.2s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <h3 style={{ 
                  margin: 0, 
                  fontSize: '16px', 
                  fontWeight: 600,
                  color: '#1e293b',
                  lineHeight: 1.4
                }}>
                  {task.title}
                </h3>
                <span style={{
                  fontSize: '12px',
                  color: getPriorityColor(task.priority),
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  marginLeft: '12px'
                }}>
                  {task.priority}
                </span>
              </div>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{
                  fontSize: '12px',
                  color: '#64748b',
                  background: '#f1f5f9',
                  padding: '4px 8px',
                  borderRadius: '4px'
                }}>
                  {task.framework}
                </span>
                <span style={{ fontSize: '12px', color: '#64748b' }}>
                  {formatTimeLeft(task.dueDate)} • {task.estimatedTime}
                </span>
              </div>
              
              <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                <button style={{
                  background: 'none',
                  border: `1px solid ${brand.primary}`,
                  color: brand.primary,
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  fontWeight: 500
                }}>
                  View Details
                </button>
                <button style={{
                  background: brand.primary,
                  border: 'none',
                  color: '#fff',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  cursor: 'pointer',
                  fontWeight: 500
                }}>
                  {task.status === 'pending' ? 'Start' : 'Continue'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* This Week's Tasks */}
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
          📅 This Week's Tasks
        </h2>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {weekTasks.map((group, index) => {
            const progress = (group.completed / group.tasks) * 100;
            return (
              <div key={index} style={{
                padding: '16px',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                background: '#fff'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <h3 style={{ 
                    margin: 0, 
                    fontSize: '16px', 
                    fontWeight: 600,
                    color: '#1e293b'
                  }}>
                    {group.framework}
                  </h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>
                    {group.completed}/{group.tasks} completed
                  </span>
                </div>
                
                {/* Progress bar */}
                <div style={{
                  width: '100%',
                  height: '6px',
                  background: '#f1f5f9',
                  borderRadius: '3px',
                  marginBottom: '12px'
                }}>
                  <div style={{
                    width: `${progress}%`,
                    height: '100%',
                    background: '#22c55e',
                    borderRadius: '3px',
                    transition: 'width 0.3s ease'
                  }} />
                </div>
                
                {/* Task items */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {group.items.slice(0, 2).map((item, itemIndex) => (
                    <div key={itemIndex} style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      fontSize: '14px',
                      color: '#64748b'
                    }}>
                      <span>{item.title}</span>
                      <span>{item.due}</span>
                    </div>
                  ))}
                  {group.items.length > 2 && (
                    <button style={{
                      background: 'none',
                      border: 'none',
                      color: brand.primary,
                      fontSize: '12px',
                      cursor: 'pointer',
                      textAlign: 'left',
                      padding: 0,
                      marginTop: '4px'
                    }}>
                      + {group.items.length - 2} more tasks
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}