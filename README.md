# 🔐 MDP_MANAGER

Un gestionnaire de mots de passe sécurisé développé en Rust, utilisant les technologies de chiffrement modernes pour protéger vos données sensibles.

## ✨ Fonctionnalités

- 🔒 **Chiffrement robuste** : AES-256-GCM pour le chiffrement des données
- 🔑 **Dérivation de clé sécurisée** : Argon2id pour la génération de clés à partir du mot de passe principal
- 💾 **Stockage local sécurisé** : Vos mots de passe restent sur votre machine
- 🦀 **Développé en Rust** : Performance et sécurité garanties par le langage

## 🛡️ Sécurité

Ce gestionnaire de mots de passe utilise les standards cryptographiques les plus avancés :

- **Argon2id** : Algorithme de dérivation de clé résistant aux attaques par force brute et par canal auxiliaire
- **AES-256-GCM** : Chiffrement authentifié garantissant la confidentialité et l'intégrité des données
- **Protection en mémoire** : Gestion sécurisée des données sensibles en mémoire

## 📋 Prérequis

- Rust 1.70 ou supérieur
- Cargo (inclus avec Rust)

## 🚀 Installation

### Depuis les sources

```bash
# Cloner le dépôt
git clone https://github.com/Azeflow10/MDP_MANAGER.git

# Naviguer dans le répertoire
cd MDP_MANAGER

# Compiler le projet
cargo build --release

# L'exécutable se trouve dans target/release/
```

## 💻 Utilisation

```bash
# Lancer l'application
cargo run

# Ou utiliser l'exécutable compilé
./target/release/mdp_manager
```

### Commandes principales

```bash
# Créer un nouveau coffre-fort
mdp_manager init

# Ajouter un nouveau mot de passe
mdp_manager add

# Récupérer un mot de passe
mdp_manager get <nom>

# Lister tous les identifiants stockés
mdp_manager list

# Supprimer un mot de passe
mdp_manager delete <nom>

# Modifier un mot de passe existant
mdp_manager update <nom>
```

## 🏗️ Architecture

```
MDP_MANAGER/
├── src/
│   ├── main.rs           # Point d'entrée de l'application
│   ├── crypto.rs         # Module de chiffrement (AES-256-GCM)
│   ├── argon.rs          # Dérivation de clé (Argon2id)
│   ├── storage.rs        # Gestion du stockage
│   └── cli.rs            # Interface en ligne de commande
├── Cargo.toml            # Dépendances du projet
└── README.md
```

## 📦 Dépendances principales

```toml
[dependencies]
argon2 = "0.5"           # Dérivation de clé
aes-gcm = "0.10"         # Chiffrement AES-256-GCM
rand = "0.8"             # Génération de nombres aléatoires
serde = "1.0"            # Sérialisation/désérialisation
clap = "4.0"             # Interface CLI
zeroize = "1.6"          # Nettoyage sécurisé de la mémoire
```

## 🔒 Bonnes pratiques

1. **Mot de passe principal fort** : Utilisez un mot de passe long et complexe
2. **Sauvegarde** : Effectuez des sauvegardes régulières de votre coffre-fort
3. **Sécurité physique** : Protégez l'accès à votre ordinateur
4. **Mises à jour** : Gardez l'application à jour pour bénéficier des derniers correctifs de sécurité

## ⚠️ Avertissements

- Ne partagez jamais votre mot de passe principal
- Conservez une sauvegarde de votre coffre-fort dans un endroit sûr
- Ce logiciel est fourni "tel quel", sans garantie d'aucune sorte

## 🛠️ Développement

### Tests

```bash
# Exécuter les tests unitaires
cargo test

# Exécuter les tests avec affichage détaillé
cargo test -- --nocapture

# Vérifier le code avec clippy
cargo clippy
```

### Formatage du code

```bash
# Formater automatiquement le code
cargo fmt

# Vérifier le formatage
cargo fmt -- --check
```

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :

1. Fork le projet
2. Créer une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 👤 Auteur

**Azeflow10**

- GitHub: [@Azeflow10](https://github.com/Azeflow10)

## 🙏 Remerciements

- La communauté Rust pour les excellentes bibliothèques cryptographiques
- Les mainteneurs des crates `argon2` et `aes-gcm`

## 📚 Ressources

- [Documentation Rust](https://doc.rust-lang.org/)
- [Argon2 RFC](https://www.rfc-editor.org/rfc/rfc9106.html)
- [AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

⭐ Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !
