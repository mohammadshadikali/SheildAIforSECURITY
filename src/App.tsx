import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { AlertQueue } from './pages/AlertQueue';
import { AlertDetail } from './pages/AlertDetail';
import { IncidentList } from './pages/IncidentList';
import { IncidentDetail } from './pages/IncidentDetail';
import { MitreHeatmap } from './pages/MitreHeatmap';
import { FileUpload } from './pages/FileUpload';
import { AuditLog } from './pages/AuditLog';
import { AIAssistant } from './pages/AIAssistant';
import { ThreatIntel } from './pages/ThreatIntel';
import { Playbooks } from './pages/Playbooks';
import { useEffect } from 'react';
import { initializeStore } from './lib/store';

export default function App() {
  useEffect(() => {
    initializeStore();
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<AlertQueue />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/incidents" element={<IncidentList />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/mitre" element={<MitreHeatmap />} />
          <Route path="/upload" element={<FileUpload />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/ai-assistant" element={<AIAssistant />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/playbooks" element={<Playbooks />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
