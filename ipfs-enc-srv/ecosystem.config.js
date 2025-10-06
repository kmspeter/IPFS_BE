module.exports = {
  apps: [{
    name: 'ipfs-enc-srv',
    script: 'server.js',
    instances: 1,
    exec_mode: 'fork',
    env: { NODE_ENV: 'production', PORT: 3000 },
    error_file: 'logs/pm2-error.log',
    out_file: 'logs/pm2-out.log',
    time: true,
    max_memory_restart: '1G',
    autorestart: true,
    wait_ready: false
  }]
};