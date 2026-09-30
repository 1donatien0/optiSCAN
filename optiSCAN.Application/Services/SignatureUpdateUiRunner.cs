namespace optiSCAN.Services
{
    /// <summary>
    /// Mise à jour manuelle des signatures avec verrou anti double-clic — extrait de <see cref="optiSCAN.MainWindow"/>.
    /// </summary>
    public sealed class SignatureUpdateUiRunner
    {
        private readonly SemaphoreSlim _lock = new(1, 1);
        private readonly SignatureUpdateService _signatureUpdate;

        public SignatureUpdateUiRunner(SignatureUpdateService signatureUpdate) =>
            _signatureUpdate = signatureUpdate;

        public SignatureUpdateUiRunner() : this(new SignatureUpdateService()) { }

        public bool TryEnterUpdate() => _lock.Wait(0);

        public void ReleaseUpdate() => _lock.Release();

        public async Task<bool> RunFullUpdateAsync(
            FreshclamUpdater? freshclam,
            YaraForgeUpdater? rules,
            Action<string> appendLog,
            CancellationToken cancellationToken = default)
        {
            return await _signatureUpdate.RunFullSignatureUpdateAsync(
                freshclam, rules, appendLog, cancellationToken).ConfigureAwait(false);
        }
    }
}
