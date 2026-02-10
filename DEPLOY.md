# Deploy to Render

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
- **Login** : https://roussel-srz.github.io/EntrepriseManagement/login.html

## Configuration

### URLs de Production
- **Backend** : https://entreprise-management-server.onrender.com
- **Frontend** : https://roussel-srz.github.io/EntrepriseManagement/

### Accès
1. Allez sur la page de login GitHub Pages
2. Connectez-vous avec `admin` / `admin123`
3. Vous serez redirigé vers l'application principale

## Notes
- Le frontend sur GitHub Pages communique avec le backend sur Render
- Les CORS sont configurés pour autoriser les requêtes cross-origin
- Le backend gère l'authentification et les données
- Le frontend gère l'interface utilisateur
