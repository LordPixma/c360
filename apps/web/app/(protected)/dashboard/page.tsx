import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../../../lib/tenant';
import { resolveBrand } from '../../../lib/branding';
import ClientGuard from './protect';
import { DashboardHeader } from './components/DashboardHeader';
import { WelcomeSection } from './components/WelcomeSection';
import { TaskManagement } from './components/TaskManagement';
import { QuickActions } from './components/QuickActions';
import { ProgressVisualization } from './components/ProgressVisualization';
import { QuickInsights } from './components/QuickInsights';

export default function DashboardPage() {
  const hdrs = headers();
  const hostname = parseHost(hdrs.get('host'));
  const { tenant } = tenantFromHost(hostname);
  const brand = resolveBrand(tenant);

  return (
    <ClientGuard>
      <div style={{ 
        minHeight: '100vh',
        background: '#f8fafc',
        fontFamily: 'system-ui, -apple-system, sans-serif'
      }}>
        {/* Add responsive styles */}
        <style>{`
          @media (max-width: 1024px) {
            .dashboard-grid {
              grid-template-columns: 1fr !important;
            }
          }
          @media (max-width: 768px) {
            .task-grid {
              grid-template-columns: 1fr !important;
            }
            .insights-grid {
              grid-template-columns: 1fr !important;
            }
          }
        `}</style>
        
        {/* Dashboard Header */}
        <DashboardHeader brand={brand} tenant={tenant} />
        
        {/* Main Content */}
        <main style={{ 
          padding: '32px 24px',
          maxWidth: '1400px',
          margin: '0 auto'
        }}>
          {/* Welcome Section */}
          <WelcomeSection brand={brand} />
          
          {/* Main Dashboard Grid */}
          <div 
            className="dashboard-grid"
            style={{ 
              display: 'grid', 
              gridTemplateColumns: '2fr 1fr', 
              gap: '32px',
              marginBottom: '32px'
            }}
          >
            {/* Left Column */}
            <div>
              {/* Task Management */}
              <TaskManagement brand={brand} />
              
              {/* Quick Actions */}
              <QuickActions brand={brand} />
            </div>
            
            {/* Right Column - Progress Visualization */}
            <ProgressVisualization brand={brand} />
          </div>
          
          {/* Bottom Section - Quick Insights */}
          <QuickInsights brand={brand} />
        </main>
      </div>
    </ClientGuard>
  );
}
