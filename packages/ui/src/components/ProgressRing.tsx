import React from 'react';

export interface ProgressRingProps {
  progress: number; // 0-100
  size?: number;
  strokeWidth?: number;
  className?: string;
  showText?: boolean;
  color?: string;
}

export function ProgressRing({ 
  progress, 
  size = 120, 
  strokeWidth = 8, 
  className = '',
  showText = true,
  color = '#3b82f6'
}: ProgressRingProps) {
  const normalizedRadius = (size - strokeWidth) / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDasharray = `${circumference} ${circumference}`;
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  return (
    <div className={`relative inline-flex items-center justify-center ${className}`}>
      <svg
        height={size}
        width={size}
        className="progress-ring"
      >
        {/* Background circle */}
        <circle
          stroke="#e5e7eb"
          fill="transparent"
          strokeWidth={strokeWidth}
          r={normalizedRadius}
          cx={size / 2}
          cy={size / 2}
        />
        {/* Progress circle */}
        <circle
          stroke={color}
          fill="transparent"
          strokeWidth={strokeWidth}
          strokeDasharray={strokeDasharray}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          r={normalizedRadius}
          cx={size / 2}
          cy={size / 2}
          className="progress-ring-circle"
        />
      </svg>
      {showText && (
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-2xl font-bold text-primary">{Math.round(progress)}%</span>
        </div>
      )}
    </div>
  );
}