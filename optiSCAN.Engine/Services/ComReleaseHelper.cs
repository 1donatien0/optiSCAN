// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace optiSCAN.Services
{
    /// <summary>Libère les RCW COM de façon explicite (évite d'attendre le GC).</summary>
    internal static class ComReleaseHelper
    {
        public static void Release(object? comObject)
        {
            if (comObject == null)
                return;

            try
            {
                if (Marshal.IsComObject(comObject))
                    Marshal.ReleaseComObject(comObject);
            }
            catch (Exception ex) when (!ex.IsFatal())
            {
                AppLogger.Warn("ComReleaseHelper", "ReleaseComObject", ex);
            }
        }
    }
}
