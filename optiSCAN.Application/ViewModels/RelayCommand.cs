using optiSCAN.Services;
#if USE_WPF_ICOMMAND
using System.Windows.Input;
#endif

namespace optiSCAN.ViewModels;

/// <summary>Commande synchrone sans dépendance à CommandManager WPF.</summary>
public sealed class RelayCommand : IRelayCommand
#if USE_WPF_ICOMMAND
    , ICommand
#endif
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => _execute(parameter);

    public void NotifyCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>Commande asynchrone sans dépendance à CommandManager WPF.</summary>
public sealed class AsyncRelayCommand : IRelayCommand
#if USE_WPF_ICOMMAND
    , ICommand
#endif
{
    private readonly Func<object?, Task> _execute;
    private readonly Func<object?, bool>? _canExecute;
    private bool _isRunning;

    public AsyncRelayCommand(Func<object?, Task> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter)
        => !_isRunning && (_canExecute?.Invoke(parameter) ?? true);

    public async void Execute(object? parameter)
    {
        _isRunning = true;
        NotifyCanExecuteChanged();
        try { await _execute(parameter).ConfigureAwait(true); }
        catch (Exception ex)
        {
            // async void : sans ce filet, une exception dans une commande (analyse, nettoyage, scan
            // planifié…) remontait jusqu'au dispatcher et fermait l'application.
            AppLogger.Error("AsyncRelayCommand", "Execute", ex);
        }
        finally
        {
            _isRunning = false;
            NotifyCanExecuteChanged();
        }
    }

    public event EventHandler? CanExecuteChanged;

    public void NotifyCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
