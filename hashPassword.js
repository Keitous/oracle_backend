const bcrypt = require('bcrypt');

// Mot de passe à hacher
const password = 'Getv2023';

// Nombre de tours de salage
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error('Erreur lors du hachage du mot de passe:', err);
    return;
  }
  console.log('Mot de passe haché:', hash);
});
