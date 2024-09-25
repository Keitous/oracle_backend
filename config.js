// config.js
require('dotenv').config();

module.exports = {
  // Secret JWT
  jwtSecret: process.env.JWT_SECRET || 'fallbackSecret',

  // Configuration de la base de données Oracle
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 1550,
    user: process.env.DB_USER || 'getv',
    password: process.env.DB_PASSWORD || 'Getv2023',
    name: process.env.DB_NAME || 'getv',
  },

  // Configuration du serveur
  server: {
    port: process.env.PORT || 3001, // Port du serveur backend
  },

  // Configuration de l'application frontend
  frontend: {
    apiUrl: process.env.REACT_APP_API_URL || 'http://localhost:3001/api',
  },

  // Autres configurations potentielles
  sessionSecret: process.env.SESSION_SECRET || 'my-session-secret',
  nodeEnv: process.env.NODE_ENV || 'development',
};
