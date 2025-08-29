"use client";

import { useState, useEffect } from 'react';
import { api } from '../../../../lib/apiClient';

interface DashboardHeaderProps {
  brand: {
    logoText: string;
    primary: string;
    secondary: string;
  };
  tenant?: string;
}

export function DashboardHeader({ brand, tenant }: DashboardHeaderProps) {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [userName] = useState('User'); // Will be replaced with actual user data
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 60000);
    return () => clearInterval(timer);
  }, []);

  const getGreeting = () => {
    const hour = currentTime.getHours();
    if (hour < 12) return 'Good morning';
    if (hour < 17) return 'Good afternoon';
    return 'Good evening';
  };

  const handleLogout = async () => {
    try {
      await api('/auth/logout', { method: 'POST' });
      location.href = '/';
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const activeTab = 'dashboard'; // Will be dynamic later

  const tabs = [
    { id: 'dashboard', label: 'My Dashboard', icon: '🏠' },
    { id: 'tasks', label: 'My Tasks', icon: '✅' },
    { id: 'training', label: 'Training', icon: '🎓' },
    { id: 'documents', label: 'Documents', icon: '📁' },
    { id: 'help', label: 'Help', icon: '❓' },
  ];

  return (
    <div style={{ background: '#fff', borderBottom: '1px solid #e2e8f0', position: 'relative' }}>
      {/* Top Bar */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        padding: '12px 24px',
        background: brand.secondary 
      }}>
        {/* Left side - Greeting and Company */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
          <div>
            <h2 style={{ 
              margin: 0, 
              fontSize: '18px', 
              color: brand.primary, 
              fontWeight: 600 
            }}>
              {getGreeting()}, {userName}
            </h2>
            <p style={{ 
              margin: 0, 
              fontSize: '14px', 
              color: '#64748b',
              marginTop: '2px'
            }}>
              {currentTime.toLocaleDateString('en-US', { 
                weekday: 'long', 
                month: 'short', 
                day: 'numeric' 
              })} • {currentTime.toLocaleTimeString('en-US', { 
                hour: '2-digit', 
                minute: '2-digit' 
              })}
            </p>
          </div>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '8px',
            padding: '8px 12px',
            background: 'rgba(255,255,255,0.7)',
            borderRadius: '8px'
          }}>
            <div style={{ 
              width: '24px', 
              height: '24px', 
              background: brand.primary, 
              borderRadius: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#fff',
              fontSize: '12px',
              fontWeight: 'bold'
            }}>
              {brand.logoText.charAt(0)}
            </div>
            <span style={{ 
              fontSize: '14px', 
              fontWeight: 600, 
              color: brand.primary 
            }}>
              {brand.logoText}
            </span>
            {tenant && (
              <span style={{ 
                fontSize: '12px', 
                color: '#64748b',
                marginLeft: '4px'
              }}>
                • {tenant}
              </span>
            )}
          </div>
        </div>

        {/* Right side - Quick Access */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button style={{
            background: 'none',
            border: 'none',
            fontSize: '20px',
            cursor: 'pointer',
            padding: '8px',
            borderRadius: '6px',
            position: 'relative'
          }}>
            🔔
            <span style={{
              position: 'absolute',
              top: '4px',
              right: '4px',
              background: '#ef4444',
              color: '#fff',
              borderRadius: '50%',
              width: '16px',
              height: '16px',
              fontSize: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              3
            </span>
          </button>
          <button style={{
            background: 'none',
            border: 'none',
            fontSize: '20px',
            cursor: 'pointer',
            padding: '8px',
            borderRadius: '6px'
          }}>
            💬
          </button>
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              style={{
                width: '32px',
                height: '32px',
                background: brand.primary,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#fff',
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none'
              }}
            >
              {userName.charAt(0)}
            </button>
            
            {showUserMenu && (
              <div style={{
                position: 'absolute',
                top: '100%',
                right: 0,
                marginTop: '8px',
                background: '#fff',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                minWidth: '200px',
                zIndex: 1000
              }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid #f1f5f9' }}>
                  <p style={{ margin: 0, fontWeight: 600, color: '#1e293b' }}>{userName}</p>
                  <p style={{ margin: 0, fontSize: '12px', color: '#64748b' }}>user@company.com</p>
                </div>
                <div style={{ padding: '8px 0' }}>
                  <button style={{
                    width: '100%',
                    background: 'none',
                    border: 'none',
                    padding: '8px 16px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    fontSize: '14px',
                    color: '#1e293b'
                  }}>
                    Profile Settings
                  </button>
                  <button style={{
                    width: '100%',
                    background: 'none',
                    border: 'none',
                    padding: '8px 16px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    fontSize: '14px',
                    color: '#1e293b'
                  }}>
                    Preferences
                  </button>
                  <hr style={{ margin: '8px 0', border: 'none', borderTop: '1px solid #f1f5f9' }} />
                  <button 
                    onClick={handleLogout}
                    style={{
                      width: '100%',
                      background: 'none',
                      border: 'none',
                      padding: '8px 16px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      fontSize: '14px',
                      color: '#dc2626'
                    }}
                  >
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ 
        display: 'flex', 
        paddingLeft: '24px',
        background: '#fff'
      }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            style={{
              background: 'none',
              border: 'none',
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              cursor: 'pointer',
              color: activeTab === tab.id ? brand.primary : '#64748b',
              borderBottom: activeTab === tab.id ? `2px solid ${brand.primary}` : '2px solid transparent',
              fontWeight: activeTab === tab.id ? 600 : 400,
              fontSize: '14px',
              transition: 'all 0.2s ease'
            }}
          >
            <span style={{ fontSize: '16px' }}>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>
      
      {/* Click outside to close menu */}
      {showUserMenu && (
        <div 
          onClick={() => setShowUserMenu(false)}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 999
          }}
        />
      )}
    </div>
  );
}