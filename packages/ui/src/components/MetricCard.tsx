import React from 'react';

export interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: string;
  className?: string;
  onClick?: () => void;
}

export function MetricCard({ 
  title, 
  value, 
  subtitle, 
  icon, 
  trend, 
  trendValue,
  className = '',
  onClick 
}: MetricCardProps) {
  const trendColors = {
    up: 'text-green-600',
    down: 'text-red-600',
    neutral: 'text-gray-500'
  };

  return (
    <div 
      className={`card p-6 hover-lift cursor-pointer animate-fade-in ${className}`}
      onClick={onClick}
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className="text-sm font-medium text-secondary mb-1">{title}</h3>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-primary">{value}</span>
            {trendValue && trend && (
              <span className={`text-sm font-medium ${trendColors[trend]}`}>
                {trend === 'up' ? '↗' : trend === 'down' ? '↘' : '→'} {trendValue}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="text-xs text-muted mt-1">{subtitle}</p>
          )}
        </div>
        {icon && (
          <div className="flex-shrink-0 ml-4">
            <div className="w-12 h-12 rounded-lg bg-blue-50 flex items-center justify-center text-blue-600">
              {icon}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}