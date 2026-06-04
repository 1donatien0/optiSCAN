namespace optiSCAN.Tests;

/// <summary>Désactive le parallélisme xUnit pour les tests mutants UserPreferences / DistractionFreeMonitor.</summary>
[CollectionDefinition("OptiscanPrefs", DisableParallelization = true)]
public sealed class OptiscanPrefsCollection;
