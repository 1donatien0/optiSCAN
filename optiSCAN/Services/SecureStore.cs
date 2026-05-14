using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services
{
    /// <summary>
    /// Persistance JSON sécurisée :
    ///   - Sérialisation JSON
    ///   - HMAC-SHA256 sur le contenu (clé dérivée du master key utilisateur)
    ///   - Chiffrement DPAPI (CurrentUser scope) sur le tout
    ///
    /// Format du fichier :
    ///   <DPAPI_blob> = encrypt({ "Hmac": "...base64...", "Json": "..." })
    ///
    /// Usage typique :
    ///   var prefs = SecureStore.Load&lt;UserPreferences&gt;(path) ?? new UserPreferences();
    ///   ...
    ///   SecureStore.Save(path, prefs);
    ///
    /// Pourquoi : les anciens stockages JSON en clair (UserPreferences,
    /// ExclusionSettings) permettaient à un attaquant local d'éditer le
    /// fichier pour ajouter des dossiers à ExcludedFolders et cacher du
    /// malware aux scans. DPAPI + HMAC empêche modification ou substitution.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SecureStore
    {
        private const string HmacInfo = "optiSCAN-securestore-hmac";

        /// <summary>
        /// Charge un objet T depuis un fichier sécurisé. Retourne default(T)
        /// si le fichier n'existe pas, est corrompu, ou si HMAC invalide.
        /// </summary>
        public static T? Load<T>(string path) where T : class
        {
            if (!File.Exists(path)) return null;

            try
            {
                var encrypted = File.ReadAllBytes(path);
                var decrypted = ProtectedData.Unprotect(encrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);

                var envelope = JsonSerializer.Deserialize<Envelope>(Encoding.UTF8.GetString(decrypted));
                if (envelope == null || string.IsNullOrEmpty(envelope.Json))
                    return null;

                // Vérification HMAC (intégrité)
                var key = DeriveHmacKey();
                try
                {
                    using var hmac = new HMACSHA256(key);
                    var expected = hmac.ComputeHash(Encoding.UTF8.GetBytes(envelope.Json));
                    var actual = Convert.FromBase64String(envelope.Hmac);
                    if (!CryptographicOperations.FixedTimeEquals(expected, actual))
                    {
                        AppLogger.Fatal("SecureStore", $"HMAC invalide pour {Path.GetFileName(path)} — refus de chargement");
                        return null;
                    }
                }
                finally { CryptographicOperations.ZeroMemory(key); }

                return JsonSerializer.Deserialize<T>(envelope.Json);
            }
            catch (CryptographicException ex)
            {
                // Échec DPAPI : changement de profil utilisateur, ou fichier copié
                // depuis une autre machine. On ne peut rien décrypter.
                AppLogger.Warn("SecureStore", $"DPAPI Unprotect échoué pour {Path.GetFileName(path)}", ex);
                return null;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SecureStore", $"Lecture {Path.GetFileName(path)}", ex);
                return null;
            }
        }

        /// <summary>
        /// Sauvegarde un objet T dans un fichier sécurisé (DPAPI + HMAC).
        /// </summary>
        public static void Save<T>(string path, T value) where T : class
        {
            try
            {
                var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = false });

                var key = DeriveHmacKey();
                string hmacB64;
                try
                {
                    using var hmac = new HMACSHA256(key);
                    var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
                    hmacB64 = Convert.ToBase64String(sig);
                }
                finally { CryptographicOperations.ZeroMemory(key); }

                var envelope = new Envelope { Json = json, Hmac = hmacB64 };
                var envelopeBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope));

                var encrypted = ProtectedData.Protect(envelopeBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);

                AtomicFile.WriteAllBytes(path, encrypted);
            }
            catch (Exception ex)
            {
                AppLogger.Error("SecureStore", $"Save {Path.GetFileName(path)}", ex);
            }
        }

        /// <summary>
        /// Tente de migrer un fichier JSON en clair (legacy) vers le format
        /// sécurisé. Retourne l'objet désérialisé si réussite, null sinon.
        /// Le fichier en clair est renommé en .legacy à la fin.
        /// </summary>
        public static T? MigrateFromPlaintext<T>(string plaintextPath, string securePath) where T : class
        {
            if (!File.Exists(plaintextPath)) return null;
            try
            {
                var json = File.ReadAllText(plaintextPath);
                var obj = JsonSerializer.Deserialize<T>(json);
                if (obj == null) return null;

                Save(securePath, obj);

                // Renommage du fichier en clair pour conserver une trace mais
                // empêcher qu'il soit relu comme source de vérité.
                try { File.Move(plaintextPath, plaintextPath + ".legacy", overwrite: true); }
                catch (Exception ex) { AppLogger.Warn("SecureStore", $"Migration cleanup {plaintextPath}", ex); }

                AppLogger.Info("SecureStore", $"Migration {Path.GetFileName(plaintextPath)} → format sécurisé");
                return obj;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("SecureStore", $"Migration {plaintextPath}", ex);
                return null;
            }
        }

        // ── Helpers privés ───────────────────────────────────────────────────────

        /// <summary>
        /// Dérive une clé HMAC stable propre à l'utilisateur Windows courant.
        /// (Une ancienne version utilisait Protect puis SHA256 : chaque appel à
        /// Protect produit un blob différent, donc la clé changeait entre Save
        /// et Load et l'HMAC était toujours rejeté.)
        /// </summary>
        private static byte[] DeriveHmacKey()
        {
            var identity =
                HmacInfo + "|" +
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "|" +
                Environment.UserDomainName + "|" +
                Environment.UserName;
            return SHA256.HashData(Encoding.UTF8.GetBytes(identity));
        }

        private class Envelope
        {
            public string Json { get; set; } = string.Empty;
            public string Hmac { get; set; } = string.Empty;
        }
    }
}
