namespace optiSCAN.Services
{
    /// <summary>Masque les chemins sensibles dans exports et journaux.</summary>
    internal static class PathRedaction
    {
        /// <summary>Remplace le profil utilisateur par <c>%UserProfile%</c>.</summary>
        public static string RedactPath(string? path)
        {
            if (string.IsNullOrEmpty(path))
                return string.Empty;

            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(profile)
                && path.StartsWith(profile, StringComparison.OrdinalIgnoreCase))
                return "%UserProfile%" + path[profile.Length..];

            // Le processus SYSTEM ne connaît que systemprofile via UserProfile. Masquer
            // aussi le segment standard des profils interactifs dans les chemins consignés
            // par le service ; le texte peut être un message d'exception contenant un chemin.
            var redacted = path;
            foreach (var marker in new[] { @"\Users\", @"\Documents and Settings\" })
            {
                var searchFrom = 0;
                while (true)
                {
                    var normalized = redacted.Replace('/', '\\');
                    var markerIndex = normalized.IndexOf(marker, searchFrom, StringComparison.OrdinalIgnoreCase);
                    if (markerIndex < 0)
                        break;

                    var userStart = markerIndex + marker.Length;
                    var userEnd = normalized.IndexOf('\\', userStart);
                    if (userStart >= normalized.Length)
                        break;

                    redacted = redacted[..userStart] + "%User%" + (userEnd >= 0 ? redacted[userEnd..] : string.Empty);
                    searchFrom = userStart + "%User%".Length;
                }
            }

            return redacted;
        }
    }
}
