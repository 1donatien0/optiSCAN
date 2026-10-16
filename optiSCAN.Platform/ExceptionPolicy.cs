// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN;

/// <summary>
/// Filtre commun des blocs <c>catch</c> : une erreur fatale du processus n'est jamais avalée.
/// </summary>
/// <remarks>
/// Avant 3.1, environ 500 blocs <c>catch</c> sans filtre interceptaient aussi un manque de mémoire ou
/// une pile épuisée. Dans l'hôte SYSTEM, le processus continuait alors dans un état incohérent au
/// lieu de s'arrêter et d'être relancé par le service. Tous les blocs généraux portent désormais
/// <c>when (!ex.IsFatal())</c> : le comportement est inchangé pour les erreurs ordinaires.
/// </remarks>
public static class ExceptionPolicy
{
    /// <summary>
    /// Vrai pour les erreurs après lesquelles le processus ne doit pas continuer : manque de
    /// mémoire (sauf <see cref="InsufficientMemoryException"/>, refus anticipé et récupérable),
    /// pile épuisée, violation d'accès, programme invalide.
    /// </summary>
    public static bool IsFatal(this Exception exception) => exception switch
    {
        InsufficientMemoryException => false,
        OutOfMemoryException => true,
        InsufficientExecutionStackException => true,
        AccessViolationException => true,
        InvalidProgramException => true,
        _ => false,
    };
}
