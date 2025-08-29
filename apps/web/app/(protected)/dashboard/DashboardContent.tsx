"use client";

import React, { useState } from 'react';
import { 
  MetricCard, 
  ProgressRing, 
  StatusBadge, 
  ActivityFeed, 
  QuickActions, 
  Sidebar, 
  Header,
  type ActivityItem,
  type QuickAction,
  type SidebarSection
} from '@c360/ui';
import { 
  Shield, 
  CheckCircle, 
  AlertTriangle, 
  Calendar,
  Home,
  FileCheck,
  Users,
  BarChart3,
  Settings,
  Plus,
  Upload,
  FileText,
  UserPlus
} from 'lucide-react';

interface DashboardContentProps {
  brand: {
    logoText: string;
    primary: string;
    secondary: string;
  };
  tenant?: string;
}

export default function DashboardContent({ brand, tenant }: DashboardContentProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Mock data for the dashboard
  const mockActivities: ActivityItem[] = [
    {
      id: '1',
      type: 'control-update',
      title: 'SOC 2 Access Control updated',
      description: 'Multi-factor authentication policy reviewed and approved',
      timestamp: '2 hours ago',
      user: { name: 'Sarah Johnson' }
    },
    {
      id: '2',
      type: 'task-completion',
      title: 'ISO 27001 Risk Assessment completed',
      description: 'Annual risk assessment for information systems',
      timestamp: '4 hours ago',
      user: { name: 'Mike Chen' }
    },
    {
      id: '3',
      type: 'evidence-upload',
      title: 'GDPR Training Certificate uploaded',
      description: 'Q4 2024 data protection training evidence',
      timestamp: '6 hours ago',
      user: { name: 'Emma Davis' }
    },
    {
      id: '4',
      type: 'user-action',
      title: 'New team member added',
      description: 'Alex Rodriguez joined the compliance team',
      timestamp: '1 day ago',
      user: { name: 'System' }
    }
  ];

  const quickActions: QuickAction[] = [
    {
      id: 'new-task',
      label: 'Create New Task',
      icon: <Plus className="w-5 h-5" />,
      onClick: () => console.log('Create new task')
    },
    {
      id: 'upload-evidence',
      label: 'Upload Evidence',
      icon: <Upload className="w-5 h-5" />,
      onClick: () => console.log('Upload evidence')
    },
    {
      id: 'generate-report',
      label: 'Generate Report',
      icon: <FileText className="w-5 h-5" />,
      onClick: () => console.log('Generate report')
    },
    {
      id: 'invite-user',
      label: 'Invite User',
      icon: <UserPlus className="w-5 h-5" />,
      onClick: () => console.log('Invite user')
    }
  ];

  const sidebarSections: SidebarSection[] = [
    {
      title: 'Main',
      items: [
        {
          id: 'dashboard',
          label: 'Dashboard',
          icon: <Home className="w-5 h-5" />,
          href: '/dashboard',
          active: true
        },
        {
          id: 'frameworks',
          label: 'Compliance Frameworks',
          icon: <Shield className="w-5 h-5" />,
          href: '/frameworks'
        },
        {
          id: 'controls',
          label: 'Controls & Evidence',
          icon: <FileCheck className="w-5 h-5" />,
          href: '/controls'
        },
        {
          id: 'tasks',
          label: 'Tasks & Workflows',
          icon: <CheckCircle className="w-5 h-5" />,
          href: '/tasks',
          badge: 12
        }
      ]
    },
    {
      title: 'Analytics',
      items: [
        {
          id: 'reports',
          label: 'Reports & Analytics',
          icon: <BarChart3 className="w-5 h-5" />,
          href: '/reports'
        },
        {
          id: 'users',
          label: 'User Management',
          icon: <Users className="w-5 h-5" />,
          href: '/users'
        },
        {
          id: 'settings',
          label: 'Settings',
          icon: <Settings className="w-5 h-5" />,
          href: '/settings'
        }
      ]
    }
  ];

  // Mock compliance frameworks data
  const frameworks = [
    {
      id: 'soc2',
      name: 'SOC 2',
      logo: '🛡️',
      progress: 92,
      status: 'certified' as const,
      controls: 23,
      evidence: 89,
      lastUpdated: '2 days ago'
    },
    {
      id: 'iso27001',
      name: 'ISO 27001',
      logo: '🔒',
      progress: 78,
      status: 'in-progress' as const,
      controls: 114,
      evidence: 156,
      lastUpdated: '1 week ago'
    },
    {
      id: 'gdpr',
      name: 'GDPR',
      logo: '🇪🇺',
      progress: 85,
      status: 'certified' as const,
      controls: 18,
      evidence: 34,
      lastUpdated: '3 days ago'
    },
    {
      id: 'hipaa',
      name: 'HIPAA',
      logo: '🏥',
      progress: 45,
      status: 'gap-identified' as const,
      controls: 32,
      evidence: 21,
      lastUpdated: '1 month ago'
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <Header
        logoText={brand.logoText}
        logoColor={brand.primary}
        user={{
          name: 'John Doe',
          email: 'john.doe@company.com'
        }}
        notifications={3}
        onSearch={(query) => console.log('Search:', query)}
        onNotificationClick={() => console.log('Notifications clicked')}
        onLogout={() => console.log('Logout')}
      />

      <div className="flex pt-16">
        {/* Sidebar */}
        <Sidebar
          sections={sidebarSections}
          collapsed={sidebarCollapsed}
          onCollapse={setSidebarCollapsed}
          className="fixed left-0 top-16 bottom-0 z-30"
        />

        {/* Main Content */}
        <main 
          className={`flex-1 transition-all duration-300 ${
            sidebarCollapsed ? 'ml-16' : 'ml-64'
          }`}
        >
          <div className="container py-8">
            {/* Welcome Section */}
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-primary mb-2">
                Welcome back{tenant ? ` to ${tenant}` : ''}!
              </h1>
              <p className="text-secondary">
                Here's your compliance overview for today.
              </p>
            </div>

            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <MetricCard
                title="Overall Compliance Score"
                value="87%"
                subtitle="↗ +5% from last month"
                trend="up"
                trendValue="+5%"
                icon={
                  <div className="relative">
                    <ProgressRing progress={87} size={48} strokeWidth={4} showText={false} />
                  </div>
                }
              />
              <MetricCard
                title="Active Frameworks"
                value="5"
                subtitle="of 7 frameworks"
                icon={<Shield className="w-6 h-6" />}
              />
              <MetricCard
                title="Overdue Tasks"
                value="12"
                subtitle="Require immediate attention"
                trend="down"
                trendValue="-3"
                icon={<AlertTriangle className="w-6 h-6 text-amber-600" />}
              />
              <MetricCard
                title="Next Audit"
                value="45"
                subtitle="days until SOC 2 audit"
                icon={<Calendar className="w-6 h-6" />}
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Compliance Frameworks */}
              <div className="lg:col-span-2">
                <h2 className="text-xl font-semibold text-primary mb-6">Compliance Frameworks</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {frameworks.map((framework) => (
                    <div key={framework.id} className="card p-6 hover-lift">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{framework.logo}</span>
                          <div>
                            <h3 className="font-semibold text-primary">{framework.name}</h3>
                            <StatusBadge status={framework.status} size="sm" />
                          </div>
                        </div>
                        <ProgressRing 
                          progress={framework.progress} 
                          size={60} 
                          strokeWidth={4}
                          showText={true}
                        />
                      </div>
                      
                      <div className="space-y-2 text-sm text-secondary">
                        <div className="flex justify-between">
                          <span>Controls:</span>
                          <span className="font-medium">{framework.controls}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Evidence:</span>
                          <span className="font-medium">{framework.evidence}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Last updated:</span>
                          <span className="font-medium">{framework.lastUpdated}</span>
                        </div>
                      </div>

                      <div className="mt-4 pt-4 border-t border-gray-100">
                        <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
                          View Details →
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Activity Feed */}
              <div className="card p-6">
                <ActivityFeed activities={mockActivities} maxItems={8} />
                <div className="mt-6 pt-4 border-t border-gray-100">
                  <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
                    View All Activity →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* Quick Actions */}
      <QuickActions actions={quickActions} />
    </div>
  );
}