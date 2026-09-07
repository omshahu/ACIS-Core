/**
 * ACIS-Core — Dashboard Application Entrypoint
 * Renders the primary Dashboard component with simulation mode defaulted to "normal".
 */

import React from 'react';
import { Dashboard } from './Dashboard';

export function DashboardApp(props) {
  return <Dashboard {...props} />;
}

export default DashboardApp;
