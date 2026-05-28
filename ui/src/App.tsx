import { Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import ScanDetail from './pages/ScanDetail';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/scans/:id" element={<ScanDetail />} />
    </Routes>
  );
}
