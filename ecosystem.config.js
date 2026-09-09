/**
 * ACIS-Core — PM2 Production Ecosystem Configuration (ACIS-Core directory context)
 * 24/7 continuous operation & monitoring configuration for Windows and Linux servers.
 *
 * Usage Commands:
 *   Start all services:        pm2 start ecosystem.config.js
 *   Start with specific env:   pm2 start ecosystem.config.js --env production
 *   Monitor live processes:    pm2 monit
 *   View unified logs:         pm2 logs
 *   Restart all gracefully:    pm2 restart ecosystem.config.js
 *   Stop all services:         pm2 stop ecosystem.config.js
 *   Save process list:         pm2 save
 *   Auto-start on system boot: pm2 startup
 */

module.exports = {
  apps: [
    // ==========================================
    // 1. ACIS-Core Backend (Flask SSE Server)
    // ==========================================
    {
      name: 'acis-core-backend',
      script: 'app.py',
      cwd: './backend',
      interpreter: 'python',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      restart_delay: 2000,
      max_restarts: 15,
      min_uptime: '10s',
      kill_timeout: 5000,
      
      error_file: './logs/backend-error.log',
      out_file: './logs/backend-out.log',
      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss.SSS',
      time: true,

      env: {
        NODE_ENV: 'development',
        FLASK_ENV: 'development',
        PORT: 5001,
        PYTHONUNBUFFERED: '1',
        ACIS_SSE_INTERVAL: '2.0'
      },
      env_production: {
        NODE_ENV: 'production',
        FLASK_ENV: 'production',
        PORT: 5001,
        PYTHONUNBUFFERED: '1',
        ACIS_SSE_INTERVAL: '2.0'
      }
    },

    // ==========================================
    // 2. ACIS-Core Frontend (Static / SPA Web Host)
    // ==========================================
    {
      name: 'acis-core-frontend',
      script: 'npx',
      args: 'serve -s . -l 3000 --cors',
      cwd: '.',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '300M',
      restart_delay: 3000,
      
      error_file: './logs/frontend-error.log',
      out_file: './logs/frontend-out.log',
      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss.SSS',
      time: true,

      env: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      }
    }
  ]
};
