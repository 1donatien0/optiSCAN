// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Http;

namespace optiSCAN.Services
{
    /// <summary>Clients HTTP conservés pour la durée du processus.</summary>
    internal static class OptiscanHttp
    {
        /// <summary>
        /// Le gestionnaire par défaut d'un <see cref="HttpClient"/> garde une connexion
        /// jusqu'à la fin du processus. Ici le pool est recyclé, pour qu'un changement
        /// DNS soit repris sans redémarrer optiSCAN.
        /// </summary>
        internal static HttpClient CreateLongLived(TimeSpan timeout)
        {
            var handler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(15),
            };
            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = timeout,
            };
        }
    }
}
