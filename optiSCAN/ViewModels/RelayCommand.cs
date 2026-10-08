using System.Windows.Input;

namespace optiSCAN
{
    /// <summary>
    /// Implémentation synchrone de ICommand.
    /// Source unique — ne pas redéfinir ailleurs dans le projet.
    /// </summary>
    public sealed class RelayCommand : ICommand
    {
        private readonly Action<object?> _execute;
        private readonly Func<object?, bool>? _canExecute;

        public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
        public void Execute(object? parameter) => _execute(parameter);
    }

    /// <summary>
    /// Implémentation asynchrone de ICommand.
    /// Source unique — ne pas redéfinir ailleurs dans le projet.
    /// </summary>
    public sealed class AsyncRelayCommand : ICommand
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
            CommandManager.InvalidateRequerySuggested();
            try
            {
                await _execute(parameter); // contexte UI conservé : la suite touche CommandManager
            }
            catch (Exception ex)
            {
                // Logguer l'exception pour éviter un crash silencieux du process
                // Les async void crashent le process si une exception n'est pas gérée
                optiSCAN.Services.AppLogger.Error("AsyncRelayCommand", "Command execution failed", ex);
            }
            finally
            {
                _isRunning = false;
                CommandManager.InvalidateRequerySuggested();
            }
        }

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }
    }
}
