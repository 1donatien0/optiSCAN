using optiSCAN.Models;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace optiSCAN.Services;

/// <summary>Page d'historique de scans (pagination).</summary>
public sealed class ScanHistoryPage
{
    public required IReadOnlyList<ScanSession> Items { get; init; }
    public int TotalCount { get; init; }
    public int Offset { get; init; }
    public int Limit { get; init; }
}

/// <summary>Persistance SQLite de l'historique scan/nettoyage (DPAPI par ligne).</summary>
[SupportedOSPlatform("windows")]
internal sealed class ScanLogSqliteStore : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly string _connectionString;
    private readonly SqliteConnection _connection;
    private readonly object _lock = new();

    public ScanLogSqliteStore(string databasePath)
    {
        var dir = Path.GetDirectoryName(databasePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
        }.ToString();
        _connection = new SqliteConnection(_connectionString);
        _connection.Open();
        EnsureSchema();
    }

    public int ScanSessionCount
    {
        get
        {
            lock (_lock)
            {
                using var cmd = _connection.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM scan_sessions;";
                return Convert.ToInt32(cmd.ExecuteScalar());
            }
        }
    }

    public IReadOnlyList<ScanSession> LoadAllScanSessions()
    {
        lock (_lock)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT payload FROM scan_sessions
                ORDER BY started_at_ticks DESC;
                """;
            return ReadScanSessions(cmd);
        }
    }

    public ScanHistoryPage LoadScanSessionsPage(int offset, int limit)
    {
        if (offset < 0) offset = 0;
        if (limit < 1) limit = 20;

        lock (_lock)
        {
            int total;
            using (var countCmd = _connection.CreateCommand())
            {
                countCmd.CommandText = "SELECT COUNT(*) FROM scan_sessions;";
                total = Convert.ToInt32(countCmd.ExecuteScalar());
            }

            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT payload FROM scan_sessions
                ORDER BY started_at_ticks DESC
                LIMIT $limit OFFSET $offset;
                """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            return new ScanHistoryPage
            {
                Items = ReadScanSessions(cmd),
                TotalCount = total,
                Offset = offset,
                Limit = limit,
            };
        }
    }

    public void ReplaceAllScanSessions(IEnumerable<ScanSession> sessions)
    {
        lock (_lock)
        {
            using var tx = _connection.BeginTransaction();
            using (var delete = _connection.CreateCommand())
            {
                delete.Transaction = tx;
                delete.CommandText = "DELETE FROM scan_sessions;";
                delete.ExecuteNonQuery();
            }

            foreach (var session in sessions)
                InsertScanSession(session, tx);

            tx.Commit();
        }
    }

    public void InsertScanSessionAtHead(ScanSession session)
    {
        lock (_lock)
        {
            using var tx = _connection.BeginTransaction();
            InsertScanSession(session, tx);
            tx.Commit();
        }
    }

    public void UpdateScanSession(ScanSession session)
    {
        lock (_lock)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                UPDATE scan_sessions
                SET started_at_ticks = $ticks, payload = $payload
                WHERE session_id = $id;
                """;
            cmd.Parameters.AddWithValue("$id", session.SessionId.ToString("D"));
            cmd.Parameters.AddWithValue("$ticks", session.StartedAt.Ticks);
            cmd.Parameters.AddWithValue("$payload", ProtectPayload(JsonSerializer.Serialize(session, JsonOptions)));
            cmd.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<CleanSession> LoadAllCleanSessions()
    {
        lock (_lock)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT payload FROM clean_sessions
                ORDER BY completed_at_ticks DESC;
                """;
            var list = new List<CleanSession>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var session = DeserializeProtected<CleanSession>(reader.GetFieldValue<byte[]>(0));
                if (session != null)
                    list.Add(session);
            }

            return list;
        }
    }

    public void ReplaceAllCleanSessions(IEnumerable<CleanSession> sessions)
    {
        lock (_lock)
        {
            using var tx = _connection.BeginTransaction();
            using (var delete = _connection.CreateCommand())
            {
                delete.Transaction = tx;
                delete.CommandText = "DELETE FROM clean_sessions;";
                delete.ExecuteNonQuery();
            }

            foreach (var session in sessions)
                InsertCleanSession(session, tx);

            tx.Commit();
        }
    }

    public void InsertCleanSessionAtHead(CleanSession session)
    {
        lock (_lock)
        {
            using var tx = _connection.BeginTransaction();
            InsertCleanSession(session, tx);
            tx.Commit();
        }
    }

    public void Dispose() => _connection.Dispose();

    private void EnsureSchema()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                session_id TEXT PRIMARY KEY,
                started_at_ticks INTEGER NOT NULL,
                payload BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_scan_sessions_started
                ON scan_sessions(started_at_ticks DESC);
            CREATE TABLE IF NOT EXISTS clean_sessions (
                session_id TEXT PRIMARY KEY,
                completed_at_ticks INTEGER NOT NULL,
                payload BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_clean_sessions_completed
                ON clean_sessions(completed_at_ticks DESC);
            """;
        cmd.ExecuteNonQuery();
    }

    private void InsertScanSession(ScanSession session, SqliteTransaction tx)
    {
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT OR REPLACE INTO scan_sessions(session_id, started_at_ticks, payload)
            VALUES ($id, $ticks, $payload);
            """;
        cmd.Parameters.AddWithValue("$id", session.SessionId.ToString("D"));
        cmd.Parameters.AddWithValue("$ticks", session.StartedAt.Ticks);
        cmd.Parameters.AddWithValue("$payload", ProtectPayload(JsonSerializer.Serialize(session, JsonOptions)));
        cmd.ExecuteNonQuery();
    }

    private void InsertCleanSession(CleanSession session, SqliteTransaction tx)
    {
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT OR REPLACE INTO clean_sessions(session_id, completed_at_ticks, payload)
            VALUES ($id, $ticks, $payload);
            """;
        cmd.Parameters.AddWithValue("$id", session.StartedAt.Ticks.ToString(CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$ticks", session.FinishedAt.Ticks);
        cmd.Parameters.AddWithValue("$payload", ProtectPayload(JsonSerializer.Serialize(session, JsonOptions)));
        cmd.ExecuteNonQuery();
    }

    private List<ScanSession> ReadScanSessions(SqliteCommand cmd)
    {
        var list = new List<ScanSession>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var session = DeserializeProtected<ScanSession>(reader.GetFieldValue<byte[]>(0));
            if (session != null)
                list.Add(session);
        }

        return list;
    }

    private static byte[] ProtectPayload(string json) =>
        ProtectedData.Protect(Encoding.UTF8.GetBytes(json), optionalEntropy: null, DataProtectionScope.CurrentUser);

    private static T? DeserializeProtected<T>(byte[] protectedBytes) where T : class
    {
        try
        {
            var json = Encoding.UTF8.GetString(
                ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser));
            return JsonSerializer.Deserialize<T>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            AppLogger.Warn("ScanLogSqliteStore", $"Ligne historique illisible ({typeof(T).Name})", ex);
            return null;
        }
    }
}
