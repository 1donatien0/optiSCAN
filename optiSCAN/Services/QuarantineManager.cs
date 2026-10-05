using optiSCAN.Models;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace optiSCAN.Services
{
    /// <summary>
    /// Quarantaine sécurisée :
    ///   - Chiffrement par fichier en AES-256-GCM (authentifié), en-tête OPTQ + nonce + tag.
    ///   - Clé maîtresse 256 bits stockée chiffrée par DPAPI (CurrentUser)
    ///   - Chaque fichier reçoit un nonce 96 bits aléatoire unique
    ///   - Le manifest est signé en HMAC-SHA256 — un manifest manipulé est rejeté
    ///
    /// Format des fichiers .quar (binaire) :
    ///   Magic:    4 octets   "OPTQ"
    ///   Version:  1 octet    0x02
    ///   Nonce:    12 octets
    ///   Tag:      16 octets  (GCM auth tag)
    ///   Cipher:   N octets   (taille = taille du fichier original)
    ///
    /// Format manifest.json :
    ///   { "Version": 2, "Hmac": "...base64...", "Entries": [...] }
    ///
    /// Pagination : <see cref="GetEntriesPaged"/> pour les grosses listes.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class QuarantineManager : IThreatStore, IDisposable
    {
        // ── Constantes format ────────────────────────────────────────────────────
        private const byte FormatVersion = 0x02;
        private const byte RawBufferXorConstant = 0x5A;
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("OPTQ");
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int HeaderSize = 4 + 1 + NonceSize + TagSize; // 33 octets

        /// <summary>Limite de taille fichier en quarantaine (plainte) pour éviter un pic RAM + OOM.</summary>
        private const long MaxQuarantinePlaintextBytes = 256L * 1024 * 1024;

        // ── Chemins ──────────────────────────────────────────────────────────────
        private readonly string _quarantineDir;
        private readonly string _manifestPath;
        private readonly string _keyPath;       // clé maîtresse chiffrée DPAPI

        // ── État ─────────────────────────────────────────────────────────────────
        private readonly byte[] _masterKey;     // 32 octets (déchiffrés en RAM)
        private QuarantineDocument _doc;
        private readonly object _lock = new();
        private ActivityLogService? _activityLog;
        private readonly IUserPreferencesAccessor _prefs;

        // ── Construction ─────────────────────────────────────────────────────────

        public QuarantineManager(string? quarantineDir = null, IUserPreferencesAccessor? preferences = null)
        {
            _prefs = preferences ?? new DefaultUserPreferencesAccessor();
            _quarantineDir = quarantineDir ?? DefaultDirectory();

            _manifestPath = Path.Combine(_quarantineDir, "manifest.json");
            _keyPath = Path.Combine(_quarantineDir, ".key");

            EnsureDirectoryExists(_quarantineDir);
            _masterKey = LoadOrCreateMasterKey();
            _doc = LoadManifest();
            UpgradeSignedManifestVersion();
            RebaseRelocatedBlobs();
            _ = Task.Run(EnsureQuarantineBlobLayout);
        }

        /// <summary>
        /// Dossier par défaut : celui de l'utilisateur, ou, pour le service SYSTEM,
        /// <c>%ProgramData%\optiSCAN\Quarantine</c> (voir <see cref="ServiceQuarantineStore"/>).
        /// </summary>
        internal static string DefaultDirectory()
        {
            if (ServiceQuarantineStore.IsServiceIdentity())
                return ServiceQuarantineStore.PrepareDirectory();

            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN", "Quarantine");
        }

        /// <summary>
        /// Le dossier a pu être déplacé (quarantaine du service reprise de l'ancien profil SYSTEM) :
        /// le manifeste garde l'ancien chemin des fichiers chiffrés. Une entrée dont le fichier
        /// manque mais dont le nom existe dans le dossier courant est rattachée à ce fichier.
        /// </summary>
        private void RebaseRelocatedBlobs()
        {
            var changed = 0;
            lock (_lock)
            {
                foreach (var entry in _doc.Entries)
                {
                    if (string.IsNullOrEmpty(entry.QuarantinePath) || File.Exists(entry.QuarantinePath))
                        continue;
                    var name = Path.GetFileName(entry.QuarantinePath);
                    if (string.IsNullOrEmpty(name))
                        continue;
                    var local = Path.Combine(_quarantineDir, name);
                    if (!File.Exists(local))
                        continue;
                    entry.QuarantinePath = local;
                    changed++;
                }

                if (changed > 0)
                {
                    SaveManifest();
                    AppLogger.Info("QuarantineManager", $"Quarantaine déplacée : {changed} entrée(s) rattachée(s) au dossier courant.");
                }
            }
        }

        public void BindActivityLog(ActivityLogService activityLog) => _activityLog = activityLog;

        private volatile bool _disposed;

        private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

        /// <summary>Efface la clé maîtresse de la mémoire ; l'instance n'est plus utilisable.</summary>
        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed)
                    return;
                _disposed = true;
                CryptographicOperations.ZeroMemory(_masterKey);
            }
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Un manifeste signé d'une version antérieure garde sa signature (calculée sur les
        /// seules entrées) : seul le numéro de version est relevé. Un manifeste <b>non signé</b>
        /// n'est jamais re-signé, quelle que soit sa version : il est refusé par
        /// <see cref="LoadManifest"/>. Sinon, écrire un manifeste « v1 » sans HMAC suffisait à
        /// faire signer des entrées arbitraires (chemin d'origine, fichier chiffré, empreinte).
        /// </summary>
        private void UpgradeSignedManifestVersion()
        {
            if (string.IsNullOrEmpty(_doc.Hmac) || _doc.Version >= 2)
                return;

            _doc.Version = 2;
            SaveManifest();
        }

        // ── Clé maîtresse (DPAPI) ────────────────────────────────────────────────

        /// <summary>
        /// Charge la clé maîtresse chiffrée par DPAPI, ou en génère une nouvelle.
        /// DPAPI CurrentUser : seul l'utilisateur courant peut déchiffrer la clé,
        /// même un autre admin de la machine ne pourra pas l'utiliser.
        /// </summary>
        private byte[] LoadOrCreateMasterKey()
        {
            try
            {
                if (File.Exists(_keyPath))
                {
                    var encrypted = File.ReadAllBytes(_keyPath);
                    return ProtectedData.Unprotect(encrypted, optionalEntropy: null, DataProtectionScope.CurrentUser);
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", "Lecture clé maîtresse", ex);
                // Clé corrompue → on la régénère. Les .quar existants deviennent illisibles sans cette clé (comportement attendu).
            }

            // Génération d'une clé 256 bits aléatoire et stockage chiffré DPAPI.
            var key = RandomNumberGenerator.GetBytes(32);
            try
            {
                var encrypted = ProtectedData.Protect(key, optionalEntropy: null, DataProtectionScope.CurrentUser);
                AtomicFile.WriteAllBytes(_keyPath, encrypted);

                // Sur Windows, on tente de marquer le fichier comme caché + system
                // pour éviter la curiosité utilisateur (best effort).
                try { File.SetAttributes(_keyPath, FileAttributes.Hidden | FileAttributes.System); }
                catch { /* best effort */ }
            }
            catch (Exception ex)
            {
                AppLogger.Error("QuarantineManager", "Persistance clé maîtresse échouée", ex);
            }
            return key;
        }

        // ── Quarantaine ──────────────────────────────────────────────────────────

        bool IThreatStore.Quarantine(ThreatInfo threat) => Quarantine(threat, default);

        int IThreatStore.QuarantineAll(IEnumerable<ThreatInfo> threats) => QuarantineAll(threats, default);

        public bool Quarantine(ThreatInfo threat, Guid sourceSessionId = default, string? expectedSha256 = null)
        {
            SafePathDelete.QuarantineHandle? source = null;
            var committed = false;
            try
            {
                // 1. Un seul accès au fichier, de la lecture à la suppression : le nom ne peut
                //    pas être remplacé entre les deux (partage en lecture seule), et aucun
                //    dossier parent ne doit être une jonction ou un lien.
                source = SafePathDelete.OpenForQuarantine(threat.FilePath);
                if (source == null)
                {
                    if (File.Exists(threat.FilePath))
                        AppLogger.Warn("QuarantineManager",
                            $"Quarantaine refusée : fichier verrouillé, lien symbolique, lien physique, ou chemin via une jonction ({threat.FilePath})");
                    return false;
                }

                var id = Guid.NewGuid().ToString("N");
                var qPath = Path.Combine(_quarantineDir, id + ".quar");

                var len = source.Length;
                if (len > MaxQuarantinePlaintextBytes)
                {
                    AppLogger.Warn("QuarantineManager",
                        $"Fichier trop volumineux pour la quarantaine ({len} octets > {MaxQuarantinePlaintextBytes}) : {threat.FilePath}");
                    return false;
                }

                var plaintext = new byte[len];
                if (!source.TryReadAll(plaintext))
                {
                    AppLogger.Warn("QuarantineManager", $"Lecture incomplète, quarantaine annulée : {threat.FilePath}");
                    return false;
                }

                // 2. Hash SHA-256 du plaintext (pour détecter une corruption à la
                //    restauration et tracer l'identité du fichier).
                var sha256 = SHA256.HashData(plaintext);
                if (expectedSha256 != null)
                {
                    byte[] expected;
                    try { expected = Convert.FromHexString(expectedSha256); }
                    catch (FormatException)
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                        return false;
                    }
                    if (expected.Length != sha256.Length || !CryptographicOperations.FixedTimeEquals(expected, sha256))
                    {
                        AppLogger.Warn("QuarantineManager", "Quarantaine refusée : le contenu a changé depuis l'analyse.");
                        CryptographicOperations.ZeroMemory(plaintext);
                        return false;
                    }
                }

                // Copie de sécurité faite à partir des octets lus, pas d'une seconde ouverture du chemin.
                if (_prefs.Current.BackupBeforeQuarantine)
                    ThreatRemediationService.TryCreateSafetyCopy(plaintext);

                // 3. Chiffrement AES-GCM avec nonce aléatoire unique.
                ThrowIfDisposed();
                var nonce = RandomNumberGenerator.GetBytes(NonceSize);
                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[TagSize];

                using (var aes = new AesGcm(_masterKey, TagSize))
                {
                    aes.Encrypt(nonce, plaintext, ciphertext, tag);
                }

                // 4. Écriture du fichier quarantaine au format binaire versionné.
                using (var fs = new FileStream(qPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    fs.Write(Magic, 0, Magic.Length);
                    fs.WriteByte(FormatVersion);
                    fs.Write(nonce, 0, nonce.Length);
                    fs.Write(tag, 0, tag.Length);
                    fs.Write(ciphertext, 0, ciphertext.Length);
                    fs.Flush(flushToDisk: true);
                }

                // 5. Suppression du fichier original par le même accès (après écriture confirmée).
                //    Elle n'a lieu qu'à la fermeture : si le manifeste ne peut pas être
                //    enregistré, elle est annulée et l'original reste en place.
                if (!source.MarkForDelete())
                {
                    AppLogger.Warn("QuarantineManager",
                        $"Suppression originale refusée après quarantaine ({threat.FilePath})");
                    try { File.Delete(qPath); } catch { /* rollback blob */ }
                    return false;
                }

                lock (_lock)
                {
                    var entry = new QuarantineEntry
                    {
                        Id = id,
                        OriginalPath = threat.FilePath,
                        QuarantinePath = qPath,
                        VirusName = threat.VirusName,
                        QuarantinedAt = DateTime.Now,
                        OriginalSize = threat.FileSize,
                        Sha256 = Convert.ToHexString(sha256),
                        SourceSessionId = sourceSessionId != Guid.Empty ? sourceSessionId : null,
                    };
                    _doc.Entries.Add(entry);
                    if (!TrySaveManifest())
                    {
                        _doc.Entries.Remove(entry);
                        source.CancelDelete();
                        try { File.Delete(qPath); } catch { /* best effort */ }
                        return false;
                    }
                    _activityLog?.RecordThreatQuarantined(entry, sourceSessionId);
                }

                // Fermeture : le fichier d'origine disparaît maintenant.
                committed = true;
                source.Dispose();
                threat.Status = ThreatStatus.Quarantined;
                threat.QuarantinePath = qPath;

                // 6. Wipe du plaintext en RAM (réduit la fenêtre d'exposition mémoire).
                CryptographicOperations.ZeroMemory(plaintext);

                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Error("QuarantineManager", $"Quarantine échec ({threat.FilePath})", ex);
                return false;
            }
            finally
            {
                // Échec après le marquage : l'original ne doit pas disparaître sans entrée de quarantaine.
                if (!committed)
                    source?.CancelDelete();
                source?.Dispose();
            }
        }

        public int QuarantineAll(IEnumerable<ThreatInfo> threats, Guid sourceSessionId = default)
        {
            int count = 0;
            foreach (var t in threats)
                if (Quarantine(t, sourceSessionId)) count++;
            return count;
        }

        // ── Restauration ─────────────────────────────────────────────────────────

        public bool Restore(string quarantineId)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;
            return RestoreToPath(entry, entry.OriginalPath);
        }

        public bool RestoreTo(string quarantineId, string destinationFolder)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;

            try
            {
                // Le nom libre (« _restored ») est choisi à la création, sans écrasement.
                var destPath = Path.Combine(destinationFolder, entry.FileName);

                if (!IsResolvedPathUnderDirectory(destPath, destinationFolder))
                {
                    AppLogger.Warn("QuarantineManager",
                        $"RestoreTo: chemin hors dossier autorisé ({destPath})");
                    return false;
                }

                return RestoreToPath(entry, destPath);
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"RestoreTo: {ex.Message}", ex);
                return false;
            }
        }

        private bool RestoreToPath(QuarantineEntry entry, string destination)
        {
            if (!File.Exists(entry.QuarantinePath)) return false;

            // Contrôle lexical d'abord ; le chemin réel est revérifié après création
            // (RestoreFileWriter) : une jonction dans le chemin ne peut pas rediriger l'écriture.
            string fullDest;
            try
            {
                fullDest = Path.GetFullPath(destination);
                if (IsSensitivePath(fullDest))
                {
                    AppLogger.Warn("QuarantineManager", $"Restauration refusée vers chemin sensible: {fullDest}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"Résolution chemin restauration: {destination}", ex);
                return false;
            }

            var plaintext = TryReadVerifiedPlaintext(entry);
            if (plaintext == null)
                return false;

            try
            {
                // Jamais d'écrasement : si le nom est pris, « nom_restored.ext », etc.
                IRestoreTarget? target = null;
                foreach (var candidate in ServiceQuarantineAdmin.CandidateNames(fullDest))
                {
                    target = RestoreFileWriter.TryCreate(candidate);
                    if (target != null)
                        break;
                }

                if (target == null)
                {
                    AppLogger.Warn("QuarantineManager", $"Restauration impossible : création refusée ({PathRedaction.RedactPath(fullDest)})");
                    return false;
                }

                using (target)
                {
                    try
                    {
                        target.Stream.Write(plaintext, 0, plaintext.Length);
                        target.Stream.Flush();
                    }
                    catch (Exception ex)
                    {
                        // Fichier partiel supprimé par la même poignée ; l'entrée reste en quarantaine.
                        AppLogger.Warn("QuarantineManager", $"Écriture de la restauration ({entry.Id})", ex);
                        target.Discard();
                        return false;
                    }
                }

                return CompleteExternalRestore(entry);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        /// <summary>Vérifie que <paramref name="candidatePath"/> résolu reste sous <paramref name="destinationFolder"/>.</summary>
        internal static bool IsResolvedPathUnderDirectory(string candidatePath, string destinationFolder)
        {
            var root = Path.GetFullPath(destinationFolder);
            if (!root.EndsWith(Path.DirectorySeparatorChar))
                root += Path.DirectorySeparatorChar;

            var full = Path.GetFullPath(candidatePath);
            return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Refuse la restauration vers les emplacements système critiques (tests via InternalsVisibleTo).</summary>
        internal static bool IsSensitivePath(string fullPath)
        {
            // Chemin vide/blanc : non sensible (conserve le comportement d'origine
            // et évite que Path.GetFullPath ne lève sur une chaîne vide).
            if (string.IsNullOrWhiteSpace(fullPath))
                return false;

            string[] forbidden =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),       // System32
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),    // SysWOW64
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),      // C:\Windows
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), // ProgramData
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            };

            // Comparaison par segment de chemin : « C:\WindowsApps » ne doit PAS être
            // considéré comme étant sous « C:\Windows ». On normalise et on exige soit
            // l'égalité exacte, soit un séparateur de répertoire après le préfixe.
            static string Normalize(string p) =>
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(p));

            var target = Normalize(fullPath);
            foreach (var f in forbidden)
            {
                if (string.IsNullOrEmpty(f)) continue;
                var root = Normalize(f);
                if (target.Equals(root, StringComparison.OrdinalIgnoreCase)
                    || target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>Déchiffre un fichier .quar en contenu clair.</summary>
        private byte[] DecryptQuarantineFile(string path)
        {
            ThrowIfDisposed();
            byte[] raw = ReadBlobBounded(path);

            // Seul le format OPTQ (AES-GCM, authentifié) est déchiffré ici. L'ancien format
            // (XOR sans MAC) n'est lu que par la migration, et seulement si son contenu
            // correspond à l'empreinte du manifeste signé.
            if (!IsV2QuarantineBlob(raw))
                throw new InvalidDataException("Format de quarantaine non authentifié (migration requise)");

            byte version = raw[4];
            if (version != FormatVersion)
                throw new InvalidDataException($"Version quarantaine inconnue : {version}");

            var nonce = new byte[NonceSize];
            var tag = new byte[TagSize];
            Array.Copy(raw, 5, nonce, 0, NonceSize);
            Array.Copy(raw, 5 + NonceSize, tag, 0, TagSize);

            int cipherLen = raw.Length - HeaderSize;
            var ciphertext = new byte[cipherLen];
            Array.Copy(raw, HeaderSize, ciphertext, 0, cipherLen);

            var plaintext = new byte[cipherLen];
            using (var aes = new AesGcm(_masterKey, TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            return plaintext;
        }

        /// <summary>Au démarrage (arrière-plan) : aligne les fichiers du manifeste sur le format .quar attendu.</summary>
        private void EnsureQuarantineBlobLayout()
        {
            try
            {
                int filesUpdated = 0;
                lock (_lock)
                {
                    foreach (var entry in _doc.Entries.ToList())
                    {
                        try
                        {
                            if (!File.Exists(entry.QuarantinePath))
                                continue;
                            var raw = ReadBlobBounded(entry.QuarantinePath);
                            if (IsV2QuarantineBlob(raw))
                                continue;

                            // Ancien format sans MAC : migré seulement si le manifeste signé
                            // en donne l'empreinte et qu'elle correspond.
                            var plaintext = DecryptWithoutQuarantineHeader(raw);
                            if (!HashMatches(plaintext, entry.Sha256))
                            {
                                AppLogger.Warn("QuarantineManager",
                                    $"Migration blob legacy refusée (empreinte absente ou invalide) pour {entry.Id}");
                                CryptographicOperations.ZeroMemory(plaintext);
                                continue;
                            }

                            var blob = BuildV2QuarantineBlob(plaintext);
                            CryptographicOperations.ZeroMemory(plaintext);
                            AtomicFile.WriteAllBytes(entry.QuarantinePath, blob);
                            filesUpdated++;
                        }
                        catch (Exception ex)
                        {
                            AppLogger.Warn("QuarantineManager", $"Fichier quarantaine ({entry.Id})", ex);
                        }
                    }

                    if (filesUpdated > 0)
                    {
                        SaveManifest();
                        AppLogger.Info("QuarantineManager",
                            $"Quarantaine : {filesUpdated} fichier(s) mis à jour.");
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", "Alignement stockage quarantaine", ex);
            }
        }

        /// <summary>Lit un fichier chiffré en refusant une taille supérieure au maximum admis en quarantaine.</summary>
        private static byte[] ReadBlobBounded(string path)
        {
            // Une seule ouverture, sans partage d'écriture : la taille contrôlée est celle du
            // fichier lu (pas de remplacement ni de croissance entre le contrôle et l'allocation).
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var length = fs.Length;
            if (length > MaxQuarantinePlaintextBytes + HeaderSize)
                throw new InvalidDataException($"Fichier de quarantaine trop volumineux ({length} octets)");
            var buffer = new byte[length];
            fs.ReadExactly(buffer);
            if (fs.ReadByte() != -1)
                throw new InvalidDataException("Fichier de quarantaine modifié pendant la lecture");
            return buffer;
        }

        /// <summary>Comparaison en temps constant d'un SHA-256 avec son écriture hexadécimale.</summary>
        internal static bool HashMatches(byte[] plaintext, string? expectedHex)
        {
            if (string.IsNullOrEmpty(expectedHex))
                return false;
            byte[] expected;
            try { expected = Convert.FromHexString(expectedHex); }
            catch (FormatException) { return false; }
            var actual = SHA256.HashData(plaintext);
            return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
        }

        private static bool IsV2QuarantineBlob(byte[] raw) =>
            raw.Length >= HeaderSize
            && raw[0] == Magic[0] && raw[1] == Magic[1]
            && raw[2] == Magic[2] && raw[3] == Magic[3];

        private static byte[] DecryptWithoutQuarantineHeader(byte[] raw)
        {
            var buffer = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++)
                buffer[i] = (byte)(raw[i] ^ RawBufferXorConstant);
            return buffer;
        }

        private byte[] BuildV2QuarantineBlob(byte[] plaintext)
        {
            ThrowIfDisposed();
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(_masterKey, TagSize))
                aes.Encrypt(nonce, plaintext, ciphertext, tag);

            var blob = new byte[HeaderSize + ciphertext.Length];
            Buffer.BlockCopy(Magic, 0, blob, 0, 4);
            blob[4] = FormatVersion;
            Buffer.BlockCopy(nonce, 0, blob, 5, NonceSize);
            Buffer.BlockCopy(tag, 0, blob, 5 + NonceSize, TagSize);
            Buffer.BlockCopy(ciphertext, 0, blob, HeaderSize, ciphertext.Length);
            return blob;
        }

        // ── Suppression / Purge ──────────────────────────────────────────────────

        public bool DeletePermanently(string quarantineId)
        {
            QuarantineEntry? entry;
            lock (_lock) { entry = _doc.Entries.Find(e => e.Id == quarantineId); }
            if (entry == null) return false;

            try
            {
                if (File.Exists(entry.QuarantinePath))
                    File.Delete(entry.QuarantinePath);

                lock (_lock)
                {
                    _activityLog?.RecordQuarantineDeleted(entry);
                    _doc.Entries.Remove(entry);
                    SaveManifest();
                }
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"DeletePermanently ({quarantineId})", ex);
                return false;
            }
        }

        /// <summary>
        /// Supprime définitivement les entrées mises en quarantaine avant <paramref name="cutoff"/>
        /// (heure locale, comme <see cref="QuarantineEntry.QuarantinedAt"/>). Politique de
        /// conservation du service : voir <see cref="ServiceQuarantineStore.RetentionDays"/>.
        /// </summary>
        public int PurgeOlderThan(DateTime cutoff)
        {
            QuarantineEntry[] expired;
            lock (_lock) { expired = _doc.Entries.Where(e => e.QuarantinedAt < cutoff).ToArray(); }
            var count = 0;
            foreach (var entry in expired)
                if (DeletePermanently(entry.Id)) count++;
            return count;
        }

        public QuarantineEntry? FindEntry(string quarantineId)
        {
            lock (_lock) { return _doc.Entries.Find(e => e.Id == quarantineId); }
        }

        /// <summary>
        /// Déchiffre une entrée et vérifie son SHA-256, sans rien écrire. Sert à la restauration
        /// faite hors de ce processus (fichier créé sous le jeton de l'administrateur).
        /// </summary>
        internal byte[]? TryReadVerifiedPlaintext(QuarantineEntry entry)
        {
            try
            {
                if (!File.Exists(entry.QuarantinePath))
                    return null;
                var plaintext = DecryptQuarantineFile(entry.QuarantinePath);
                // AES-GCM authentifie déjà le contenu ; l'empreinte du manifeste lie en plus
                // le fichier chiffré à son entrée.
                if (!string.IsNullOrEmpty(entry.Sha256) && !HashMatches(plaintext, entry.Sha256))
                {
                    AppLogger.Warn("QuarantineManager", $"SHA-256 mismatch pour {entry.Id}");
                    CryptographicOperations.ZeroMemory(plaintext);
                    return null;
                }

                return plaintext;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"Lecture de l'entrée {entry.Id}", ex);
                return null;
            }
        }

        /// <summary>Après une restauration écrite ailleurs : retire l'entrée et son fichier chiffré.</summary>
        internal bool CompleteExternalRestore(QuarantineEntry entry)
        {
            try
            {
                if (File.Exists(entry.QuarantinePath))
                    File.Delete(entry.QuarantinePath);
                lock (_lock)
                {
                    _activityLog?.RecordThreatRestored(entry);
                    _doc.Entries.Remove(entry);
                    SaveManifest();
                }
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Warn("QuarantineManager", $"Fin de restauration ({entry.Id})", ex);
                return false;
            }
        }

        public int PurgeAll()
        {
            int count = 0;
            QuarantineEntry[] snapshot;
            lock (_lock) { snapshot = _doc.Entries.ToArray(); }
            foreach (var entry in snapshot)
                if (DeletePermanently(entry.Id)) count++;
            return count;
        }

        /// <summary>
        /// Fenêtre paginée sur les entrées — évite de copier toute la liste côté UI.
        /// </summary>
        public IReadOnlyList<QuarantineEntry> GetEntriesPaged(int offset, int count)
        {
            if (offset < 0) offset = 0;
            if (count <= 0)
                return Array.Empty<QuarantineEntry>();
            lock (_lock)
            {
                var list = _doc.Entries;
                if (offset >= list.Count)
                    return Array.Empty<QuarantineEntry>();
                var take = Math.Min(count, list.Count - offset);
                return list.GetRange(offset, take);
            }
        }

        /// <remarks>Copie : la liste interne change pendant les quarantaines et restaurations.</remarks>
        public IReadOnlyList<QuarantineEntry> GetEntries()
        {
            lock (_lock) { return _doc.Entries.ToArray(); }
        }

        /// <summary>Les <paramref name="count"/> entrées les plus récentes, sans copier tout le manifeste.</summary>
        internal IReadOnlyList<QuarantineEntry> GetNewestEntries(int count)
        {
            lock (_lock)
            {
                return _doc.Entries
                    .OrderByDescending(e => e.QuarantinedAt)
                    .Take(Math.Max(0, count))
                    .ToArray();
            }
        }

        public int Count
        {
            get { lock (_lock) { return _doc.Entries.Count; } }
        }

        public long TotalSize
        {
            get { lock (_lock) { return _doc.Entries.Sum(e => e.OriginalSize > 0 ? e.OriginalSize : 0); } }
        }

        // ── Manifest avec HMAC-SHA256 ────────────────────────────────────────────

        /// <summary>
        /// Charge le manifest en vérifiant la signature HMAC.
        /// Si la signature ne correspond pas, on log et on retourne un manifest vide
        /// — refus de charger un manifest manipulé.
        /// </summary>
        private QuarantineDocument LoadManifest()
        {
            return AtomicFile.ReadWithBackup(
                _manifestPath,
                json =>
                {
                    var doc = JsonSerializer.Deserialize<QuarantineDocument>(json) ?? new QuarantineDocument();

                    // Vérification HMAC : on recalcule sur la liste d'entries
                    // sérialisée canoniquement, et compare avec le HMAC stocké.
                    if (!string.IsNullOrEmpty(doc.Hmac))
                    {
                        var expected = ComputeHmac(doc.Entries);
                        if (!CryptographicOperations.FixedTimeEquals(
                                Convert.FromBase64String(doc.Hmac),
                                expected))
                        {
                            AppLogger.Fatal("QuarantineManager", "HMAC manifest invalide — refus de chargement");
                            throw new InvalidDataException("Manifest HMAC invalide");
                        }
                    }
                    else if (doc.Entries.Count > 0)
                    {
                        // Quelle que soit la version déclarée : un manifeste non signé n'est pas fiable.
                        AppLogger.Fatal("QuarantineManager", $"Manifeste sans HMAC (version {doc.Version}) — refus de chargement");
                        throw new InvalidDataException("Manifest unsigned");
                    }

                    return doc;
                },
                fallbackValue: new QuarantineDocument());
        }

        private bool TrySaveManifest()
        {
            try
            {
                _doc.Version = 2;
                _doc.Hmac = Convert.ToBase64String(ComputeHmac(_doc.Entries));

                var json = JsonSerializer.Serialize(_doc, new JsonSerializerOptions
                {
                    WriteIndented = true,
                });
                AtomicFile.WriteAllText(_manifestPath, json);
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Error("QuarantineManager", "SaveManifest", ex);
                return false;
            }
        }

        private void SaveManifest()
        {
            if (!TrySaveManifest())
                AppLogger.Warn("QuarantineManager", "SaveManifest ignoré (échec silencieux évité)");
        }

        /// <summary>
        /// Calcule le HMAC-SHA256 sur la sérialisation canonique des entries.
        /// La clé HMAC est dérivée de la clé maîtresse via HKDF (label différent
        /// pour ne pas réutiliser la même clé entre AES-GCM et HMAC).
        /// </summary>
        private byte[] ComputeHmac(List<QuarantineEntry> entries)
        {
            ThrowIfDisposed();
            // Dérivation : HMAC-key = HKDF(_masterKey, "optiSCAN-manifest-hmac")
            var hmacKey = HKDF.DeriveKey(
                hashAlgorithmName: HashAlgorithmName.SHA256,
                ikm: _masterKey,
                outputLength: 32,
                salt: null,
                info: Encoding.ASCII.GetBytes("optiSCAN-manifest-hmac"));

            // Sérialisation canonique : on prend les entries sans le champ Hmac
            // pour éviter la circularité, dans un ordre stable.
            var canonical = JsonSerializer.Serialize(
                entries.OrderBy(e => e.Id, StringComparer.Ordinal).ToList());

            using var hmac = new HMACSHA256(hmacKey);
            var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical));

            CryptographicOperations.ZeroMemory(hmacKey);
            return sig;
        }

        private static void EnsureDirectoryExists(string dir)
        {
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
        }
    }

    // ── Document persisté ────────────────────────────────────────────────────────

    /// <summary>Container persisté du manifest (versionné + signé).</summary>
    public class QuarantineDocument
    {
        public int Version { get; set; } = 2;

        /// <summary>Signature HMAC-SHA256 base64 du contenu Entries.</summary>
        public string Hmac { get; set; } = string.Empty;

        public List<QuarantineEntry> Entries { get; set; } = new();
    }

    public class QuarantineEntry
    {
        public string Id { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public string VirusName { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; }
        public long OriginalSize { get; set; }

        /// <summary>Hash SHA-256 hex du fichier original (vérifié à la restauration).</summary>
        public string Sha256 { get; set; } = string.Empty;

        /// <summary>Session scan d'origine si connue (traçabilité Historique).</summary>
        /// <remarks>
        /// Omis du JSON quand il est absent : le HMAC du manifeste est calculé sur la
        /// sérialisation des entrées. Les entrées écrites par la version 1 n'ont pas ce
        /// champ ; l'écrire à <c>null</c> changeait l'empreinte, le manifeste v1 était
        /// refusé (« HMAC manifest invalide ») et la quarantaine v1 disparaissait.
        /// </remarks>
        [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        public Guid? SourceSessionId { get; set; }

        public string FileName => Path.GetFileName(OriginalPath);
        public string SizeDisplay => OriginalSize >= 0
            ? OriginalSize < 1024 ? $"{OriginalSize} o"
            : OriginalSize < 1048576 ? $"{OriginalSize / 1024.0:F1} Ko"
            : $"{OriginalSize / 1048576.0:F1} Mo"
            : "Inconnu";
    }
}
