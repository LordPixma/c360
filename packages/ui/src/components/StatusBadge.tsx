import React from 'react';

export interface StatusBadgeProps {
  status: 'certified' | 'in-progress' | 'gap-identified' | 'not-started';
  text?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function StatusBadge({ 
  status, 
  text, 
  size = 'md', 
  className = '' 
}: StatusBadgeProps) {
  const statusConfig = {
    'certified': {
      color: 'bg-green-100 text-green-800 border-green-200',
      text: text || 'Certified',
      icon: '✓'
    },
    'in-progress': {
      color: 'bg-blue-100 text-blue-800 border-blue-200',
      text: text || 'In Progress',
      icon: '⟳'
    },
    'gap-identified': {
      color: 'bg-amber-100 text-amber-800 border-amber-200',
      text: text || 'Gap Identified',
      icon: '⚠'
    },
    'not-started': {
      color: 'bg-gray-100 text-gray-800 border-gray-200',
      text: text || 'Not Started',
      icon: '○'
    }
  };

  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-3 py-1 text-sm',
    lg: 'px-4 py-2 text-base'
  };

  const config = statusConfig[status];

  return (
    <span 
      className={`inline-flex items-center gap-1 rounded-full border font-medium ${config.color} ${sizeClasses[size]} ${className}`}
    >
      <span className="text-current">{config.icon}</span>
      {config.text}
    </span>
  );
}