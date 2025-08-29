import React, { useState } from 'react';

export interface QuickAction {
  id: string;
  label: string;
  icon: React.ReactNode;
  onClick: () => void;
}

export interface QuickActionsProps {
  actions: QuickAction[];
  className?: string;
}

export function QuickActions({ actions, className = '' }: QuickActionsProps) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className={`fixed bottom-6 right-6 z-50 ${className}`}>
      {/* Action menu items */}
      {isOpen && (
        <div className="mb-4 space-y-2 animate-scale-in">
          {actions.map((action, index) => (
            <div
              key={action.id}
              className="flex items-center justify-end"
              style={{ animationDelay: `${index * 0.05}s` }}
            >
              <span className="bg-gray-800 text-white text-sm px-3 py-1 rounded-lg mr-3 opacity-90">
                {action.label}
              </span>
              <button
                onClick={() => {
                  action.onClick();
                  setIsOpen(false);
                }}
                className="w-12 h-12 bg-white rounded-full shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 flex items-center justify-center text-blue-600 border border-gray-200"
              >
                {action.icon}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Main FAB button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`w-14 h-14 bg-blue-600 hover:bg-blue-700 rounded-full shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 flex items-center justify-center text-white relative ${
          isOpen ? 'rotate-45' : ''
        }`}
      >
        <svg
          className="w-6 h-6"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 4v16m8-8H4"
          />
        </svg>
      </button>
    </div>
  );
}