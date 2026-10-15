namespace optiSCAN.Services;

/// <summary>Commande UI agnostique (WPF / WinUI) — remplace System.Windows.Input.ICommand dans la couche Application.</summary>
public interface IRelayCommand
{
    event EventHandler? CanExecuteChanged;

    bool CanExecute(object? parameter);

    void Execute(object? parameter);
}
