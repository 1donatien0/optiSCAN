using System.Windows;

namespace optiSCAN.Services
{
    /// <summary>
    /// Contrat de navigation entre les panneaux principaux.
    /// Permet de découpler la logique de navigation de la MainWindow (SRP).
    /// </summary>
    public interface INavigationService
    {
        /// <summary>Nom du panneau actuellement affiché.</summary>
        string CurrentView { get; }

        /// <summary>Déclenché après chaque changement de vue.</summary>
        event EventHandler<string>? Navigated;

        /// <summary>Enregistre un panneau sous un nom de clé.</summary>
        void RegisterPanel(string name, UIElement panel);

        /// <summary>Rend visible le panneau correspondant, masque les autres.</summary>
        void NavigateTo(string name);

        /// <summary>Indique si un panneau est enregistré.</summary>
        bool HasPanel(string name);
    }

    /// <summary>
    /// Implémentation concrète de la navigation par visibilité WPF.
    /// Tous les panneaux sont gardés en mémoire ; seul le panneau actif est visible.
    /// </summary>
    public class NavigationService : INavigationService
    {
        private readonly Dictionary<string, UIElement> _panels = new(StringComparer.OrdinalIgnoreCase);

        public string CurrentView { get; private set; } = string.Empty;

        /// <inheritdoc/>
        public event EventHandler<string>? Navigated;

        /// <inheritdoc/>
        public void RegisterPanel(string name, UIElement panel)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Le nom du panneau ne peut pas être vide.", nameof(name));

            ArgumentNullException.ThrowIfNull(panel);

            if (!_panels.ContainsKey(name))
                _panels.Add(name, panel);
        }

        /// <inheritdoc/>
        public void NavigateTo(string name)
        {
            if (!_panels.TryGetValue(name, out var target))
            {
                AppLogger.Warn("NavigationService", $"Panneau inconnu : '{name}'");
                return;
            }

            // Masquer tous les panneaux
            foreach (var panel in _panels.Values)
                panel.Visibility = Visibility.Collapsed;

            // Afficher la cible
            target.Visibility = Visibility.Visible;
            CurrentView = name;

            Navigated?.Invoke(this, name);
        }

        /// <inheritdoc/>
        public bool HasPanel(string name)
            => !string.IsNullOrWhiteSpace(name) && _panels.ContainsKey(name);
    }
}
