// SPDX-License-Identifier: GPL-3.0-or-later
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
    ///   - HMAC-SHA256 sur le contenu (clé aléatoire 256 bits protégée par DPAPI)
    ///   - Chiffrement DPAPI (CurrentUser scope) sur le tout
    ///
    /// Format du fichier :
    ///   <DPAPI_blob> = encrypt({ "Hmac": "...base64...", "Json": "..." })
    ///
    /// Migration : les fichiers signés avec l’ancienne dérivation déterministe
    /// (profil utilisateur) sont rechargés puis ré-enregistrés avec la nouvelle clé.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SecureStore
    {

        private static string HmacKeyPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "optiSCAN", ".securestore_hmac.key");

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

                if (!string.IsNullOrEmpty(envelope.Hmac))
                {
                    var dpapiKey = TryLoadDpapiHmacKey();
                    try
                    {
                        if (dpapiKey != null && TryVerifyHmac(envelope, dpapiKey))
                            return JsonSerializer.Deserialize<T>(envelope.Json);

                        // L'ancienne clé HMAC se déduisait d'informations publiques (nom du
                        // compte, profil) : n'importe qui pouvait signer un fichier « valide ».
                        // Elle n'est plus acceptée, même pour une migration.
                        AppLogger.Fatal("SecureStore",
                            $"HMAC invalide pour {Path.GetFileName(path)} — refus de chargement");
                        return null;
                    }
                    finally
                    {
                        if (dpapiKey != null)
                            CryptographicOperations.ZeroMemory(dpapiKey);
                    }
                }

                AppLogger.Fatal("SecureStore",
                    $"Enveloppe sans HMAC refusée pour {Path.GetFileName(path)}");
                return null;
            }
            catch (CryptographicException ex)
            {
                AppLogger.Warn("SecureStore", $"DPAPI Unprotect échoué pour {Path.GetFileName(path)}", ex);
                return null;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("SecureStore", $"Lecture {Path.GetFileName(path)}", ex);
                return null;
            }
        }

        /// <summary>
        /// Sauvegarde un objet T dans un fichier sécurisé (DPAPI + HMAC).
        /// </summary>
        public static void Save<T>(string path, T value) where T : class => TrySave(path, value);

        /// <summary>Comme <see cref="Save{T}"/>, mais rend faux si l'écriture a échoué.</summary>
        public static bool TrySave<T>(string path, T value) where T : class
        {
            try
            {
                var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = false });

                var key = GetOrCreateDpapiHmacKeyMaterial();
                string hmacB64;
                try
                {
                    using var hmac = new HMACSHA256(key);
                    var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
                    hmacB64 = Convert.ToBase64String(sig);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }

                var envelope = new Envelope { Json = json, Hmac = hmacB64 };
                var envelopeBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope));

                var encrypted = ProtectedData.Protect(envelopeBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);

                AtomicFile.WriteAllBytes(path, encrypted);
                return true;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Error("SecureStore", $"Save {Path.GetFileName(path)}", ex);
                return false;
            }
        }

        /// <summary>
        /// Tente de migrer un fichier JSON en clair (legacy) vers le format
        /// sécurisé. Retourne l'objet désérialisé si la lecture a réussi, null sinon.
        /// Le fichier en clair n'est supprimé que si la version sécurisée a été écrite
        /// <b>et relue</b> ; sinon il reste en place et la migration sera retentée.
        /// </summary>
        public static T? MigrateFromPlaintext<T>(string plaintextPath, string securePath) where T : class
        {
            if (!File.Exists(plaintextPath)) return null;
            try
            {
                var json = File.ReadAllText(plaintextPath);
                var obj = JsonSerializer.Deserialize<T>(json);
                if (obj == null) return null;

                // Une panne d'écriture (disque plein, DPAPI indisponible) ne doit pas faire perdre
                // les données : sans copie sécurisée relisible, le fichier en clair est conservé.
                if (!TrySave(securePath, obj) || Load<T>(securePath) == null)
                {
                    AppLogger.Warn("SecureStore",
                        $"Migration {Path.GetFileName(plaintextPath)} non confirmée : fichier en clair conservé, nouvel essai au prochain démarrage");
                    return obj;
                }

                // Le fichier en clair est supprimé (et non plus conservé en « .legacy ») :
                // ses données sensibles ne doivent pas rester lisibles à côté de la version chiffrée.
                try
                {
                    File.Delete(plaintextPath);
                    var oldLegacy = plaintextPath + ".legacy";
                    if (File.Exists(oldLegacy))
                        File.Delete(oldLegacy);
                }
                catch (Exception ex) when (!ex.IsFatal()) { AppLogger.Warn("SecureStore", $"Migration cleanup {plaintextPath}", ex); }

                AppLogger.Info("SecureStore", $"Migration {Path.GetFileName(plaintextPath)} → format sécurisé");
                return obj;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("SecureStore", $"Migration {plaintextPath}", ex);
                return null;
            }
        }

        // ── Helpers privés ───────────────────────────────────────────────────────

        private static bool TryVerifyHmac(Envelope envelope, byte[] key)
        {
            try
            {
                using var hmac = new HMACSHA256(key);
                var expected = hmac.ComputeHash(Encoding.UTF8.GetBytes(envelope.Json));
                var actual = Convert.FromBase64String(envelope.Hmac);
                return CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch (Exception ignored) when (!ignored.IsFatal())
            {
                return false;
            }
        }

        private static byte[]? TryLoadDpapiHmacKey()
        {
            if (!File.Exists(HmacKeyPath))
                return null;
            try
            {
                var dec = ProtectedData.Unprotect(
                    File.ReadAllBytes(HmacKeyPath),
                    optionalEntropy: null,
                    DataProtectionScope.CurrentUser);
                return dec.Length == 32 ? dec : null;
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("SecureStore", "Lecture clé HMAC DPAPI", ex);
                return null;
            }
        }

        /// <summary>
        /// Clé aléatoire 256 bits persistée sous DPAPI. Une clé présente mais illisible est
        /// conservée à part avant d'être remplacée : les fichiers qu'elle signait restent
        /// récupérables après une panne DPAPI passagère.
        /// </summary>
        private static byte[] GetOrCreateDpapiHmacKeyMaterial()
        {
            var existing = TryLoadDpapiHmacKey();
            if (existing != null)
                return existing;
            if (File.Exists(HmacKeyPath))
                AtomicFile.PreserveAside(HmacKeyPath, "unreadable");

            var key = RandomNumberGenerator.GetBytes(32);
            try
            {
                var enc = ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);
                var dir = Path.GetDirectoryName(HmacKeyPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                AtomicFile.WriteAllBytes(HmacKeyPath, enc);
                try { File.SetAttributes(HmacKeyPath, FileAttributes.Hidden | FileAttributes.System); }
                catch (Exception ignored) when (!ignored.IsFatal()) { /* best effort */ }
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Error("SecureStore", "Persistance clé HMAC DPAPI", ex);
            }
            return key;
        }

        private class Envelope
        {
            public string Json { get; set; } = string.Empty;
            public string Hmac { get; set; } = string.Empty;
        }
    }
}
