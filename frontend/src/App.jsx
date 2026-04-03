import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import CustomCursor from './components/CustomCursor';
import BackgroundEffects from './components/BackgroundEffects';
import Toast from './components/Toast';
import Login from './pages/Login';
import DashboardLayout from './components/DashboardLayout';
import Overview from './pages/Overview';
import Clients from './pages/Clients';
import Alerts from './pages/Alerts';
import Analytics from './pages/Analytics';
import Simulator from './pages/Simulator';

export default function App() {
  return (
    <>
      <CustomCursor />
      <BackgroundEffects />
      <Toast />
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />
        <Route element={<DashboardLayout />}>
          <Route path="/overview" element={<Overview />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/simulator" element={<Simulator />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}
