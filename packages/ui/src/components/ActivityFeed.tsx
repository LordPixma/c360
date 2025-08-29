import React from 'react';

export interface ActivityItem {
  id: string;
  type: 'control-update' | 'task-completion' | 'evidence-upload' | 'user-action';
  title: string;
  description?: string;
  timestamp: string;
  user?: {
    name: string;
    avatar?: string;
  };
}

export interface ActivityFeedProps {
  activities: ActivityItem[];
  className?: string;
  maxItems?: number;
}

export function ActivityFeed({ activities, className = '', maxItems = 10 }: ActivityFeedProps) {
  const typeConfig = {
    'control-update': {
      color: 'bg-green-500',
      icon: '🛡️'
    },
    'task-completion': {
      color: 'bg-blue-500',
      icon: '✅'
    },
    'evidence-upload': {
      color: 'bg-purple-500',
      icon: '📄'
    },
    'user-action': {
      color: 'bg-gray-500',
      icon: '👤'
    }
  };

  const displayedActivities = activities.slice(0, maxItems);

  return (
    <div className={`space-y-4 ${className}`}>
      <h3 className="text-lg font-semibold text-primary mb-4">Recent Activity</h3>
      <div className="space-y-3">
        {displayedActivities.map((activity, index) => {
          const config = typeConfig[activity.type];
          return (
            <div key={activity.id} className="flex items-start gap-3 animate-fade-in" style={{ animationDelay: `${index * 0.1}s` }}>
              <div className={`w-8 h-8 rounded-full ${config.color} flex items-center justify-center text-white text-sm flex-shrink-0`}>
                {config.icon}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-primary truncate">
                    {activity.title}
                  </p>
                  <span className="text-xs text-muted ml-2">{activity.timestamp}</span>
                </div>
                {activity.description && (
                  <p className="text-sm text-secondary mt-1">{activity.description}</p>
                )}
                {activity.user && (
                  <div className="flex items-center gap-2 mt-2">
                    {activity.user.avatar ? (
                      <img 
                        src={activity.user.avatar} 
                        alt={activity.user.name}
                        className="w-4 h-4 rounded-full"
                      />
                    ) : (
                      <div className="w-4 h-4 rounded-full bg-gray-300"></div>
                    )}
                    <span className="text-xs text-muted">{activity.user.name}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}