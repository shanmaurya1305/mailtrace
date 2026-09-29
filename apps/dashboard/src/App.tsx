import { useState, useEffect, useCallback } from 'react';
import { Routes, Route } from 'react-router-dom';
import { Header } from './components/Header';
import { Navigation } from './components/Navigation';
import { DashboardOverview } from './pages/Dashboard';
import { ForensicWorkbench } from './pages/Investigation';
import { PlatformSettings } from './pages/Settings';
import { fetchHealth } from './services/api';
import { HealthCheckResponse } from '../../../shared/types';

export function App() {
  const [health, setHealth] = useState<HealthCheckResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const checkApiHealth = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchHealth();
      setHealth(data);
      setError(null);
    } catch (err: any) {
      setHealth(null);
      setError(err?.message || 'Failed to connect to API');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkApiHealth();
    // Poll health status every 10 seconds
    const interval = setInterval(checkApiHealth, 10000);
    return () => clearInterval(interval);
  }, [checkApiHealth]);

  const apiStatus = health && health.status === 'ok' ? 'connected' : loading ? 'checking' : 'pending';

  return (
    <div className="min-h-screen bg-[#0a0d14] text-gray-100 flex flex-col">
      <Header apiStatus={apiStatus} serviceName={health?.service} />
      <div className="flex-1 flex">
        <Navigation />
        <main className="flex-1 p-6 overflow-y-auto">
          <Routes>
            <Route
              path="/"
              element={
                <DashboardOverview
                  health={health}
                  loading={loading}
                  error={error}
                  onRefresh={checkApiHealth}
                />
              }
            />
            <Route path="/investigation" element={<ForensicWorkbench />} />
            <Route path="/settings" element={<PlatformSettings />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;
