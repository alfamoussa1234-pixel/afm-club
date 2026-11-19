# AFM — Afrique Football Management

Application web de gestion du club **AFM** :

- **Administration** : tableau de bord, joueurs, matchs et résultats, entraînements et présences, finances, annonces, traitement des absences déclarées, comptes d'accès.
- **Espace joueur** : annonces, calendrier, statistiques personnelles, déclaration d'absences, notifications quand l'administration répond.

Technique : Node.js (sans framework) + PostgreSQL. Une seule dépendance : `pg`.

---

## 1. Mettre le projet sur GitHub

1. Créez un compte sur <https://github.com> si besoin.
2. Cliquez sur **New repository**, nommez-le par exemple `afm-club`, choisissez **Private**, puis **Create repository**.
3. Envoyez les fichiers, avec l'une de ces deux méthodes :
   - **Sans ligne de commande** : sur la page du dépôt vide, cliquez sur *uploading an existing file*, glissez **tout le contenu** du dossier `afm-club` (y compris le dossier `public`), puis *Commit changes*.
   - **Avec Git** (dans le dossier `afm-club`) :
     ```bash
     git init
     git add .
     git commit -m "Application AFM"
     git branch -M main
     git remote add origin https://github.com/VOTRE-COMPTE/afm-club.git
     git push -u origin main
     ```

> Les fichiers `.gitignore` et `.env.example` commencent par un point. Avec le glisser-déposer, ils peuvent être masqués. Ce n'est pas grave : l'application fonctionne sans eux.

## 2. Créer la base de données

Les données (joueurs, matchs, finances…) doivent être dans une base PostgreSQL. Le disque d'un service Render gratuit est effacé à chaque redémarrage : il ne faut donc pas y stocker de données.

Deux options :

| Option | Coût | Remarque |
|---|---|---|
| **Neon** (<https://neon.tech>) | Gratuit sans limite de durée | Recommandé pour commencer |
| **Render Postgres** | Payant (environ 6 $/mois) | La version gratuite de Render est **supprimée après 30 jours** : ne l'utilisez pas pour les vraies données du club |

**Avec Neon** : créez un compte, puis un projet (région la plus proche : Europe). Copiez la **connection string**, qui commence par `postgresql://…`. C'est votre `DATABASE_URL`.

L'application crée elle-même sa table au premier démarrage.

## 3. Déployer sur Render

1. Créez un compte sur <https://render.com> et connectez votre compte GitHub.
2. Cliquez sur **New → Blueprint**, puis choisissez le dépôt `afm-club`. Render lit le fichier `render.yaml`.
3. Render vous demande deux valeurs :
   - `ADMIN_PASSWORD` : le mot de passe du premier compte administrateur (identifiant `admin`) ;
   - `DATABASE_URL` : l'adresse copiée à l'étape 2.
4. Validez avec **Apply**. Après 2 à 3 minutes, l'application est en ligne à une adresse du type `https://afm-club.onrender.com`.

<details>
<summary>Sans Blueprint (création manuelle)</summary>

**New → Web Service**, puis choisissez le dépôt :

- Runtime : **Node**
- Build Command : `npm install`
- Start Command : `npm start`
- Variables d'environnement : `SESSION_SECRET` (une longue phrase aléatoire), `ADMIN_USERNAME` (`admin`), `ADMIN_PASSWORD`, `DATABASE_URL`, `NODE_VERSION` (`22`)
</details>

### Bon à savoir sur l'offre gratuite de Render

Un service gratuit **se met en veille après 15 minutes sans visite**. La visite suivante prend environ une minute à s'afficher. Pour éviter cette attente, passez le service à l'offre *Starter* (payante).

## 4. Première connexion

1. Ouvrez l'adresse de l'application et connectez-vous avec `admin` et le mot de passe choisi.
2. Cliquez sur votre nom en haut à droite pour **changer le mot de passe**.
3. Allez dans **Paramètres** pour renseigner le nom du club, la saison, le stade et la cotisation.
4. Ajoutez vos **joueurs**. Pour chacun, cliquez sur **Créer son accès** : l'application génère un identifiant et un mot de passe à envoyer au joueur (WhatsApp, SMS…).
5. Pour les membres du staff, créez un compte avec le rôle **Administration**.

## 5. Tester sur votre ordinateur (facultatif)

Il faut Node.js 20 ou plus récent.

```bash
cp .env.example .env      # puis modifiez ADMIN_PASSWORD et SESSION_SECRET
npm install
node --env-file=.env server.js
```

Ouvrez ensuite <http://localhost:3000>. Sans `DATABASE_URL`, les données sont enregistrées dans `data/afm-data.json`.

## Sécurité

- Les mots de passe sont chiffrés (scrypt) et ne sont jamais stockés en clair.
- Après 10 essais de connexion ratés, l'accès est bloqué 15 minutes.
- Les joueurs ne voient ni les finances, ni les téléphones des autres joueurs, ni leurs demandes d'absence.
- Une demande déjà traitée par l'administration ne peut plus être modifiée par le joueur.
- Ne publiez jamais le fichier `.env` ni votre `DATABASE_URL`.

## Sauvegarde

Dans **Paramètres → Données**, le bouton *Copier une sauvegarde* copie toutes les données au format JSON. Neon garde aussi un historique de la base.
