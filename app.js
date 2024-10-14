require('dotenv').config();  // Charger les variables d'environnement depuis le fichier .env
const express = require('express');
const oracledb = require('oracledb');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const dbConfig = require('./dbConfig');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Fonction middleware pour vérifier le token d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Assumes token is in "Bearer TOKEN" format

  if (token == null) return res.sendStatus(401); // No token provided

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token

    req.user = user; // Attach user information to request
    next(); // Proceed to the next middleware or route handler
  });
};

const app = express();
const router = express.Router(); // Crée une instance de Router
//app.use(cors());
app.use(cors({
  origin: 'https://oracle-frontend.onrender.com', // Remplace par l'URL de ton frontend
}));
app.use(bodyParser.json());
app.use(express.json());

// Route de base
app.get('/', (req, res) => {
  res.send('Bienvenue sur le serveur de gestion électronique des tickets de voyage!');
});

// Route pour vérifier la première connexion
app.get('/api/check-first-login/:login', async (req, res) => {
  const { login } = req.params;

  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute(
      `SELECT FLAG_CONNEXION FROM GETV.TD_USER WHERE LOWER(NOM_ACCES) = :login`,
      [login.toLowerCase()]
    );

    if (result.rows.length > 0) {
      const flagConnexion = result.rows[0][0];
      res.json({ isFirstLogin: flagConnexion === 'N' });
    } else {
      res.status(404).send('Utilisateur non trouvé.');
    }

    await connection.close();
  } catch (err) {
    console.error('Erreur lors de la vérification de la première connexion:', err);
    res.status(500).send('Une erreur est survenue. Veuillez réessayer plus tard.');
  }
});

// Route pour mettre à jour le mot de passe lors de la première connexion
app.post('/api/update-password', async (req, res) => {
  const { login, newPassword } = req.body;

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    const connection = await oracledb.getConnection(dbConfig);
    await connection.execute(
      `UPDATE GETV.TD_USER SET PASSWORD_HASH = :password_hash, FLAG_CONNEXION = 'O' WHERE LOWER(NOM_ACCES) = :login`,
      [hashedPassword, login.toLowerCase()],
      { autoCommit: true }
    );

    res.json({ message: 'Mot de passe mis à jour avec succès' });
    await connection.close();
  } catch (err) {
    console.error('Erreur lors de la mise à jour du mot de passe:', err);
    res.status(500).send('Une erreur est survenue. Veuillez réessayer plus tard.');
  }
});

// Route pour la connexion
app.post('/api/login', async (req, res) => {
  const { login, password, newPassword, defaultPassword } = req.body;

  try {
    const connection = await oracledb.getConnection(dbConfig);
    
    // Requête pour vérifier les informations de connexion
    const result = await connection.execute(
      `SELECT PASSWORD_HASH, FLAG_CONNEXION FROM GETV.TD_USER WHERE LOWER(NOM_ACCES) = :login`,
      [login.toLowerCase()]
    );

    if (result.rows.length > 0) {
      const storedPasswordHash = result.rows[0][0];
      const flagConnexion = result.rows[0][1];

      if (flagConnexion === 'N') {
        // Première connexion avec mise à jour du mot de passe
        if (!defaultPassword || !newPassword) {
          return res.json({ success: false, message: 'Veuillez fournir tous les champs requis pour la première connexion.' });
        }

        const matchDefault = await bcrypt.compare(defaultPassword, storedPasswordHash);

        if (!matchDefault) {
          return res.json({ success: false, message: 'Mot de passe par défaut incorrect.' });
        }

        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        await connection.execute(
          `UPDATE GETV.TD_USER SET PASSWORD_HASH = :newPasswordHash, FLAG_CONNEXION = 'O' WHERE LOWER(NOM_ACCES) = :login`,
          [hashedNewPassword, login.toLowerCase()],
          { autoCommit: true }
        );

        const token = jwt.sign({ login }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token });
      } else {
        // Connexion normale
        if (!password) {
          return res.json({ success: false, message: 'Veuillez fournir le mot de passe.' });
        }

        const match = await bcrypt.compare(password, storedPasswordHash);

        if (match) {
          const token = jwt.sign({ login }, process.env.JWT_SECRET, { expiresIn: '1h' });
          res.json({ success: true, token });
        } else {
          res.json({ success: false, message: 'Nom d\'utilisateur ou mot de passe incorrect' });
        }
      }
    } else {
      res.json({ success: false, message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }

    await connection.close();
  } catch (err) {
    console.error('Erreur lors de la connexion:', err);
    res.status(500).send('Une erreur est survenue. Veuillez réessayer plus tard.');
  }
});

// Route pour ajouter un utilisateur
app.post('/api/users', /*authenticateToken,*/ async (req, res) => {
  const { nom_acces, nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu } = req.body;

  // Mot de passe par défaut à hasher
  const defaultPassword = 'password123'; // Remplacez par un mot de passe par défaut sécurisé

  try {
    // Génération du hash du mot de passe par défaut
    const saltRounds = 10; // Nombre de tours pour le hachage
    const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);

    // Connexion à la base de données Oracle
    const connection = await oracledb.getConnection(dbConfig);

    // Récupération du libelle_fonction_role correspondant au code_fonction_role sélectionné
    const result = await connection.execute(
      `SELECT libelle_fonction_role 
       FROM GETV.TC_FONCTION_ROLE 
       WHERE code_fonction_role = :code_fonction_role`,
      [code_fonction_role]
    );

    // Vérifier si un libelle_fonction_role a été trouvé
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Code fonction rôle non trouvé' });
    }

    // Récupération du libelle_fonction_role
    const libelle_fonction_role = result.rows[0][0]; // Supposant que le libelle_fonction_role est dans la première colonne

    // Insertion de l'utilisateur avec le libelle_fonction_role récupéré
    await connection.execute(
      `INSERT INTO GETV.TD_USER 
       (NOM_ACCES, NOM_USER, PRENOM_USER, FLAG_CONNEXION, CODE_TYPE_GESTION, CODE_FONCTION_ROLE,  CODE_FONCTION, PASSWORD_HASH, CODE_MENU, ROLE) 
       VALUES (:nom_acces, :nom_user, :prenom_user, :flag_connexion, :code_type_gestion, :code_fonction_role,  :code_fonction, :password_hash, :code_menu, :libelle_fonction_role)`,
      [nom_acces, nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role,  code_fonction, hashedPassword, code_menu, libelle_fonction_role],
      { autoCommit: true }
    );

    // Envoi de la réponse au client
    res.json({ message: 'Utilisateur ajouté avec succès' });

    // Fermeture de la connexion
    await connection.close();
  } catch (err) {
    // Gestion des erreurs
    console.error('Erreur lors de l\'ajout de l\'utilisateur:', err);
    res.status(500).send(err.message);
  }
});

// Route pour afficher les utilisateurs
app.get('/api/users', async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT nom_acces, nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu, role FROM GETV.TD_USER');
    res.json(result.rows);
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour mettre à jour un utilisateur
app.put('/api/users/:nom_acces', async (req, res) => {
  const { nom_acces } = req.params;
  const { nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu, role} = req.body;
  
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute(
      `UPDATE GETV.TD_USER 
       SET NOM_USER = :nom_user, 
           PRENOM_USER = :prenom_user,
           FLAG_CONNEXION = :flag_connexion,
           CODE_TYPE_GESTION = :code_type_gestion,
           CODE_FONCTION_ROLE = :code_fonction_role,
           CODE_FONCTION = :code_fonction,
           CODE_MENU = :code_menu,
           ROLE = :role
       WHERE NOM_ACCES = :nom_acces`,
      [nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu, role, nom_acces],
      { autoCommit: true }
    );
    

    if (result.rowsAffected > 0) {
      res.json({ message: 'Utilisateur modifié avec succès' });
    } else {
      res.status(404).send('Utilisateur non trouvé');
    }

    await connection.close();
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir un utilisateur par NOM_ACCES
app.get('/api/users/:nom_acces', async (req, res) => {
  const { nom_acces } = req.params;
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT nom_acces, nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu, role FROM GETV.TD_USER WHERE lower(NOM_ACCES) = :nom_acces', [nom_acces]);
    
    // Assure-toi que le format de la réponse est correct
    if (result.rows.length > 0) {
      const [nom_acces, nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu, role] = result.rows[0];
      res.json({ nom_acces, nom_user, prenom_user, flag_connexion, code_type_gestion, code_fonction_role, code_fonction, code_menu, role });
    } else {
      res.status(404).send('Utilisateur non trouvé');
    }
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir les véhicules
app.get('/api/vehicules', /*authenticateToken,*/ async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT * FROM GETV.TC_VEHICULE');
    res.json(result.rows);
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour ajouter un véhicule
app.post('/api/vehicules', async (req, res) => {
  const { code_vehicule, libelle_vehicule, nombre_place_assise } = req.body;

  // Validation des champs requis
  if (!code_vehicule || !libelle_vehicule || nombre_place_assise === undefined) {
    return res.status(400).json({ message: 'Tous les champs sont requis' });
  }

  try {
    const connection = await oracledb.getConnection(dbConfig);

    // Exécution de l'insertion dans la base de données
    await connection.execute(
      `INSERT INTO GETV.TC_VEHICULE (CODE_VEHICULE, LIBELLE_VEHICULE, NOMBRE_PLACE_ASSISE) 
       VALUES (:code_vehicule, :libelle_vehicule, :nombre_place_assise)`,
      [code_vehicule, libelle_vehicule, nombre_place_assise],
      { autoCommit: true }
    );
    

    // Réponse réussie
    res.json({ message: 'Véhicule ajouté avec succès' });
    await connection.close();
  } catch (err) {
    // Gestion des erreurs
    console.error('Error inserting vehicle:', err);
    res.status(500).send(err.message);
  }
});

// Route pour mettre à jour un vehicule
app.put('/api/vehicules/:code_vehicule', async (req, res) => {
  const { code_vehicule } = req.params;
  const { libelle_vehicule, nombre_place_assise } = req.body;
  try {
    const connection = await oracledb.getConnection(dbConfig);
    await connection.execute(
      `UPDATE GETV.TC_VEHICULE 
       SET LIBELLE_VEHICULE = :libelle_vehicule, 
           NOMBRE_PLACE_ASSISE = :nombre_place_assise 
       WHERE CODE_VEHICULE = :code_vehicule`,
      [libelle_vehicule, nombre_place_assise, code_vehicule],
      { autoCommit: true }
    );
    
    res.json({ message: 'Véhicule modifiée avec succès' });
    await connection.close();
  } catch (err) {
    console.error('Error updating vehicule:', err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir une vehicule par CODE_VEHICULE
app.get('/api/vehicules/:code_vehicule', async (req, res) => {
  const { code_vehicule } = req.params;
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT * FROM GETV.TC_VEHICULE WHERE CODE_VEHICULE = :code_vehicule', [code_vehicule]);
    
    // Assure-toi que le format de la réponse est correct
    if (result.rows.length > 0) {
      const [code_vehicule, libelle_vehicule, nombre_place_assise] = result.rows[0];
      res.json({ code_vehicule, libelle_vehicule, nombre_place_assise });
    } else {
      res.status(404).send('Vehicule non trouvée');
    }
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour afficher les destinations
app.get('/api/destinations', async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT * FROM GETV.TC_DESTINATION');
    res.json(result.rows);
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour ajouter une destination
app.post('/api/destinations', async (req, res) => {
  console.log(req.body);  // Affiche les données reçues du frontend
  const { codeDestination, libelleDestination, prixDestination } = req.body;  // Correspond aux noms reçus du frontend
  try {
    const connection = await oracledb.getConnection(dbConfig);
    await connection.execute(
      `INSERT INTO GETV.TC_DESTINATION (CODE_DESTINATION, LIBELLE_DESTINATION, PRIX_DESTINATION) 
       VALUES (:codeDestination, :libelleDestination, :prixDestination)`,
       [codeDestination, libelleDestination, prixDestination],  // Utiliser les bonnes variables
       { autoCommit: true }
    );
    
    res.json({ message: 'Destination ajoutée avec succès' });
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour mettre à jour une destination
app.put('/api/destinations/:code_destination', async (req, res) => {
  const { code_destination } = req.params;
  const { libelle_destination, prix_destination } = req.body;
  try {
    const connection = await oracledb.getConnection(dbConfig);
    await connection.execute(
      `UPDATE GETV.TC_DESTINATION 
       SET LIBELLE_DESTINATION = :libelle_destination, 
           PRIX_DESTINATION = :prix_destination 
       WHERE CODE_DESTINATION = :code_destination`,
      [libelle_destination, prix_destination, code_destination],
      { autoCommit: true }
    );
    
    res.json({ message: 'Destination modifiée avec succès' });
    await connection.close();
  } catch (err) {
    console.error('Error updating destination:', err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir une destination par CODE_DESTINATION
app.get('/api/destinations/:code_destination', async (req, res) => {
  const { code_destination } = req.params;
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT * FROM GETV.TC_DESTINATION WHERE CODE_DESTINATION = :code_destination', [code_destination]);
    
    // Assure-toi que le format de la réponse est correct
    if (result.rows.length > 0) {
      const [code_destination, libelle_destination, prix_destination] = result.rows[0];
      res.json({ code_destination, libelle_destination, prix_destination });
    } else {
      res.status(404).send('Destination non trouvée');
    }
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir les types de gestion
app.get('/api/type-gestion', async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT code_type_gestion,libelle_type_gestion FROM GETV.TC_TYPE_GESTION');
    res.json(result.rows);
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir les fonctions rôle (inchangée)
app.get('/api/fonction-role', async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT code_fonction_role, libelle_fonction_role FROM GETV.TC_FONCTION_ROLE');
    
    // Envoi des résultats sous forme de JSON
    res.json(result.rows);

    // Fermeture de la connexion
    await connection.close();
  } catch (err) {
    // Gestion des erreurs
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir les fonctions
app.get('/api/fonction', async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT code_fonction,libelle_fonction FROM GETV.TC_FONCTION');
    res.json(result.rows);
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Route pour obtenir les menus
app.get('/api/menu', async (req, res) => {
  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute('SELECT code_menu,libelle_menu FROM GETV.TC_MENU');
    res.json(result.rows);
    await connection.close();
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message);
  }
});

// Utiliser le router pour les routes API
app.use('/api', router);

// Assurez-vous que les fichiers statiques sont servis depuis le répertoire 'client/build'
//app.use(express.static(path.join(__dirname, 'client/build')));

// Route pour servir le frontend (React, par exemple)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});
 
// Démarrez le serveur
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
