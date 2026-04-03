import { useState } from 'react';
import Sidebar from './components/Sidebar.jsx';
import Overview from './pages/Overview.jsx';
import Analytics from './pages/Analytics.jsx';
import Simulator from './pages/Simulator.jsx';
import Clients from './pages/Clients.jsx';

const PAGES = {
  overview: Overview,
  analytics: Analytics,
  simulator: Simulator,
  clients: Clients,
};

export default function App() {
  const [activePage, setActivePage] = useState('overview');
  const ActiveComponent = PAGES[activePage] || Overview;

  return (
    <div className="app-layout">
      <Sidebar activePage={activePage} setPage={setActivePage} />
      <main className="main-content">
        <ActiveComponent />
      </main>
    </div>
  );
}
