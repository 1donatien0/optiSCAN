// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows;
using System.Windows.Media.Animation;

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
            {
                panel.Opacity = panel.Visibility == Visibility.Visible ? 1 : 0;
                _panels.Add(name, panel);
            }
        }

        /// <inheritdoc/>
        public void NavigateTo(string name)
        {
            if (!_panels.TryGetValue(name, out var target))
            {
                AppLogger.Warn("NavigationService", $"Panneau inconnu : '{name}'");
                return;
            }

            foreach (var panel in _panels.Values)
            {
                if (panel == target) continue;
                panel.BeginAnimation(UIElement.OpacityProperty, null);
                panel.Opacity = 0;
                panel.Visibility = Visibility.Collapsed;
            }

            // Pas de fondu 0→1 : démarré avant l'affichage de la fenêtre, il reste
            // figé à 0 et l'accueil s'ouvre vide alors que la barre latérale est là.
            target.Visibility = Visibility.Visible;
            target.BeginAnimation(UIElement.OpacityProperty, null);
            target.Opacity = 1;

            CurrentView = name;
            Navigated?.Invoke(this, name);
        }

        /// <inheritdoc/>
        public bool HasPanel(string name)
            => !string.IsNullOrWhiteSpace(name) && _panels.ContainsKey(name);
    }
}
