const crypto = require('crypto');

// Génère une clé aléatoire de 64 octets, puis convertit en base64
const key = crypto.randomBytes(64).toString('base64');
console.log(key);
