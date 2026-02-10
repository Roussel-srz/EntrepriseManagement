# Enterprise Management Pro - Multi-User Version v2.3

Système de gestion d'entreprise multi-utilisateur avec authentification, permissions en temps réel et collaboration.

## 🚀 Fonctionnalités

### Multi-Utilisateur
- **Authentification sécurisée** avec JWT
- **Gestion des rôles** : Administrateur, Gestionnaire, Utilisateur
- **Permissions granulaires** pour chaque module
- **Sessions utilisateur** avec suivi de connexion
- **Audit logs** pour toutes les actions

### Modules de Gestion
- **Tableau de bord** : Statistiques en temps réel
- **Gestion de stock** : Inventaire et produits
- **Ventes & Facturation** : POS et suivi des ventes
- **Crédits Clients** : Gestion des créances
- **Dépenses & Caisse** : Suivi des dépenses
- **Rapports** : Export PDF et analyses
- **Logs Système** : Journal des activités
- **Gestion Utilisateurs** : Administration (admin seulement)

### Collaboration en Temps Réel
- **Synchronisation instantanée** des données
- **Notifications** en temps réel
- **Utilisateurs actifs** affichés dans l'interface
- **Collaboration** sur les mêmes données

## 📋 Prérequis

- Node.js 14+ 
- npm ou yarn
- Navigateur web moderne

## 🛠️ Installation

1. **Cloner le projet**
```bash
git clone <repository-url>
cd EntrepriseMulti
```

2. **Installer les dépendances**
```bash
npm install
```

3. **Démarrer le serveur**
```bash
npm start
```

Ou en mode développement :
```bash
npm run dev
```

4. **Accéder à l'application**
Ouvrez `http://localhost:3000` dans votre navigateur

## 🔐 Configuration par Défaut

**Identifiants Admin :**
- Nom d'utilisateur : `admin`
- Mot de passe : `admin123`

> ⚠️ **Important** : Changez ces identifiants après la première connexion !

## 📁 Structure du Projet

```
EntrepriseMulti/
├── backend/
│   ├── server.js          # Serveur principal Express
│   └── auth.js            # Module d'authentification
├── index.html             # Application principale
├── login.html             # Page de connexion
├── package.json           # Dépendances Node.js
└── README.md              # Documentation
```

## 👥 Rôles et Permissions

### Administrateur
- Accès à tous les modules
- Gestion des utilisateurs
- Configuration système
- Vue complète des rapports

### Gestionnaire
- Gestion des ventes et stocks
- Création de rapports
- Pas d'accès à la gestion des utilisateurs

### Utilisateur
- Ventes et facturation
- Consultation des données
- Permissions limitées selon la configuration

## 🔧 API Endpoints

### Authentification
- `POST /api/auth/login` - Connexion
- `POST /api/auth/logout` - Déconnexion
- `GET /api/auth/me` - Informations utilisateur

### Gestion Utilisateurs (Admin seulement)
- `GET /api/users` - Lister les utilisateurs
- `POST /api/users` - Créer un utilisateur
- `PUT /api/users/:id` - Modifier un utilisateur
- `DELETE /api/users/:id` - Supprimer un utilisateur

## 🔄 Synchronisation en Temps Réel

L'application utilise Socket.IO pour :
- Synchroniser les données entre utilisateurs
- Afficher les utilisateurs connectés
- Notifier des changements importants
- Maintenir un audit des actions

## 📊 Base de Données

Le système utilise SQLite avec les tables suivantes :
- `users` - Informations des utilisateurs
- `user_sessions` - Sessions actives
- `audit_logs` - Journal d'audit
- Tables de l'application (ventes, produits, etc.)

## 🔒 Sécurité

- **Hashage des mots de passe** avec bcrypt
- **Tokens JWT** pour l'authentification
- **Permissions vérifiées** côté serveur
- **Audit complet** des actions
- **Sessions sécurisées** avec expiration

## 🚀 Déploiement

### Production
1. Configurez les variables d'environnement :
```bash
export JWT_SECRET=votre-secret-securise
export PORT=3000
```

2. Démarrez avec PM2 ou autre process manager :
```bash
pm2 start backend/server.js --name enterprise-app
```

### Docker (optionnel)
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

## 🐛 Dépannage

### Problèmes Communs

1. **Port déjà utilisé**
   - Changez le port avec `PORT=3001 npm start`

2. **Erreur de connexion**
   - Vérifiez que le serveur est démarré
   - Nettoyez le localStorage du navigateur

3. **Permissions refusées**
   - Vérifiez le rôle de l'utilisateur
   - Contactez un administrateur

## 📞 Support

Pour toute question ou problème :
- Consultez les logs du serveur
- Vérifiez la console du navigateur
- Contactez l'administrateur système

## 📝 Mises à Jour

Cette version v2.3 inclut :
- Multi-utilisateur complet
- Authentification JWT
- Synchronisation temps réel
- Gestion des permissions
- Interface responsive améliorée
- Audit complet des actions

---

© 2024 Goaka Enterprise Solutions - Tous droits réservés
