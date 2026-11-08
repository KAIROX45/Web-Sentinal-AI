import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppLayout } from './layouts/AppLayout';
import { Home } from './pages/Home';
import { Dashboard } from './pages/Dashboard';
import { URLAnalysis } from './pages/URLAnalysis';
import { TLSAnalysis } from './pages/TLSAnalysis';
import { HeadersAnalysis } from './pages/HeadersAnalysis';
import { MessageAnalysis } from './pages/MessageAnalysis';
import { IPAnalysis } from './pages/IPAnalysis';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { BlockchainVerificationPage } from './pages/BlockchainVerification';
import { InvestigationHistoryPage } from './pages/InvestigationHistory';
import { SettingsPage } from './pages/Settings';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout />}>
          <Route index element={<Home />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="url" element={<URLAnalysis />} />
          <Route path="tls" element={<TLSAnalysis />} />
          <Route path="headers" element={<HeadersAnalysis />} />
          <Route path="message" element={<MessageAnalysis />} />
          <Route path="ip" element={<IPAnalysis />} />
          <Route path="threats" element={<ThreatIntelligence />} />
          <Route path="blockchain" element={<BlockchainVerificationPage />} />
          <Route path="history" element={<InvestigationHistoryPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;
