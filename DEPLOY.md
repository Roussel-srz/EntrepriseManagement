# Deploy to Render - Multi-Enterprise Architecture

## Backend Deployment

1. Connectez-vous à [Render](https://render.com)
2. Créez un nouveau **Web Service**
3. Connectez votre repository GitHub
4. Configurez :
   - **Name** : entreprise-management-server
   - **Runtime** : Node
   - **Build Command** : `npm install`
   - **Start Command** : `node backend/server.js`
   - **Environment Variables** :
     - `JWT_SECRET` : votre-secret-securise
     - `PORT` : 3000

## Frontend Deployment (GitHub Pages)

Le frontend est déployé sur GitHub Pages :
- **URL** : https://roussel-srz.github.io/EntrepriseManagement/
- **Login Multi-Entreprises** : https://roussel-srz.github.io/EntrepriseManagement/login-multi.html

## Architecture Multi-Entreprises

### 🏢 **Système Multi-Entreprises**
Chaque entreprise a sa propre base de données isolée :
- **Clé d'entreprise unique** : Identifie chaque entreprise
- **Base de données séparée** : `./databases/{companyKey}.db`
- **Isolation complète** : Les données ne se mélangent jamais
- **Admin par entreprise** : Chaque entreprise a son propre admin

### 🔐 **Processus de Connexion**
1. **Inscription** : Créer une nouvelle entreprise avec clé unique
2. **Connexion** : Utiliser la clé + identifiants admin
3. **Accès** : Redirection vers l'application avec contexte entreprise

### 📊 **Gestion des Données**
- **Isolation** : Chaque entreprise ne voit que ses données
- **Sécurité** : Les clés d'entreprise protègent l'accès
- **Scalabilité** : Nombre illimité d'entreprises
- **Backup** : Base de données par entreprise

## Configuration

### URLs de Production
- **Backend** : https://entreprise-management-server.onrender.com
- **Frontend** : https://roussel-srz.github.io/EntrepriseManagement/
- **Login Multi** : https://roussel-srz.github.io/EntrepriseManagement/login-multi.html

### Accès
1. Allez sur la page login-multi GitHub Pages
2. **Créez votre entreprise** ou **connectez-vous** avec une clé existante
3. Vous serez redirigé vers l'application avec votre contexte entreprise

## Exemples

### 🏪 **Entreprise Démo**
- **Clé** : `demo`
- **Admin** : `admin` / `admin123`
- **URL** : https://roussel-srz.github.io/EntrepriseManagement/login-multi.html

### 🏭 **Entreprise Personnalisée**
- **Clé** : `ma-entreprise-123`
- **Admin** : `admin` / `admin123`
- **Base de données** : `./databases/ma-entreprise-123.db`

## Notes
- Le frontend sur GitHub Pages communique avec le backend sur Render
- Les CORS sont configurés pour autoriser les requêtes cross-origin
- Le backend gère l'authentification et les données multi-entreprises
- Le frontend gère l'interface utilisateur avec contexte entreprise
- Chaque entreprise a sa propre base de données SQLite
- Les données sont complètement isolées entre entreprises
