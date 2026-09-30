using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace optiSCAN.Models;

/// <summary>Élément sélectionnable dans la page Nettoyer (virtualisation ListView).</summary>
public sealed class CleanupItem : INotifyPropertyChanged
{
    private bool _isSelected;
    private string _details = string.Empty;

    public string Id { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public bool IsBrowser { get; init; }

    public string Details
    {
        get => _details;
        set { if (_details != value) { _details = value; OnPropertyChanged(); } }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected != value) { _isSelected = value; OnPropertyChanged(); } }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
