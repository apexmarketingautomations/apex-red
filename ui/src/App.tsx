import { Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import InvestigationDetail from './pages/InvestigationDetail';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/investigations/:id" element={<InvestigationDetail />} />
    </Routes>
  );
}
