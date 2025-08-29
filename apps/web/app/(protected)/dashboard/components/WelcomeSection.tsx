"use client";

interface WelcomeSectionProps {
  brand: {
    primary: string;
  };
}

export function WelcomeSection({ brand }: WelcomeSectionProps) {
  const completionPercentage = 87; // Mock data
  const tasksRemaining = 3;
  
  const achievements = [
    { name: 'Task Master', icon: '🎯', earned: true },
    { name: 'Evidence Expert', icon: '📋', earned: true },
    { name: 'Team Player', icon: '🤝', earned: false },
    { name: 'Streak Keeper', icon: '🔥', earned: true },
  ];

  return (
    <div style={{ 
      background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
      borderRadius: '12px',
      padding: '32px',
      color: '#fff',
      marginBottom: '32px',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Decorative elements */}
      <div style={{
        position: 'absolute',
        top: '-50px',
        right: '-50px',
        width: '200px',
        height: '200px',
        background: 'rgba(255,255,255,0.1)',
        borderRadius: '50%'
      }} />
      <div style={{
        position: 'absolute',
        bottom: '-30px',
        left: '-30px',
        width: '100px',
        height: '100px',
        background: 'rgba(255,255,255,0.05)',
        borderRadius: '50%'
      }} />

      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'auto 1fr auto', 
        gap: '32px',
        alignItems: 'center',
        position: 'relative',
        zIndex: 1
      }}>
        {/* Progress Ring */}
        <div style={{ 
          position: 'relative',
          width: '120px',
          height: '120px'
        }}>
          <svg width="120" height="120" style={{ transform: 'rotate(-90deg)' }}>
            {/* Background circle */}
            <circle
              cx="60"
              cy="60"
              r="50"
              fill="none"
              stroke="rgba(255,255,255,0.2)"
              strokeWidth="8"
            />
            {/* Progress circle */}
            <circle
              cx="60"
              cy="60"
              r="50"
              fill="none"
              stroke="#22c55e"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${2 * Math.PI * 50}`}
              strokeDashoffset={`${2 * Math.PI * 50 * (1 - completionPercentage / 100)}`}
              style={{ transition: 'stroke-dashoffset 1s ease' }}
            />
          </svg>
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '24px', fontWeight: 700 }}>
              {completionPercentage}%
            </div>
            <div style={{ fontSize: '12px', opacity: 0.9 }}>
              Complete
            </div>
          </div>
        </div>

        {/* Welcome Message */}
        <div>
          <h1 style={{ 
            margin: 0, 
            fontSize: '28px', 
            fontWeight: 700,
            marginBottom: '8px'
          }}>
            You're doing great! 🎉
          </h1>
          <p style={{ 
            margin: 0, 
            fontSize: '18px', 
            opacity: 0.9,
            marginBottom: '16px'
          }}>
            {tasksRemaining} tasks to complete this week
          </p>
          <p style={{ 
            margin: 0, 
            fontSize: '14px', 
            opacity: 0.8
          }}>
            Keep up the excellent work! You're ahead of schedule and making great progress on your compliance goals.
          </p>
        </div>

        {/* Achievement Badges */}
        <div>
          <h3 style={{ 
            margin: 0, 
            fontSize: '16px', 
            fontWeight: 600,
            marginBottom: '16px',
            opacity: 0.9
          }}>
            Recent Achievements
          </h3>
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: '12px'
          }}>
            {achievements.map((achievement, index) => (
              <div
                key={index}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '8px 12px',
                  background: achievement.earned 
                    ? 'rgba(34, 197, 94, 0.2)' 
                    : 'rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  opacity: achievement.earned ? 1 : 0.5,
                  border: achievement.earned 
                    ? '1px solid rgba(34, 197, 94, 0.3)' 
                    : '1px solid rgba(255,255,255,0.2)'
                }}
              >
                <span style={{ fontSize: '16px' }}>{achievement.icon}</span>
                <span style={{ 
                  fontSize: '12px', 
                  fontWeight: 500,
                  whiteSpace: 'nowrap'
                }}>
                  {achievement.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}