using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using MatchmakingService.Configuration;

namespace MatchmakingService.Services;

internal sealed record AccountRecord(Guid PlayerId, string NormalizedEmail, string PasswordHash);

internal enum CreateAccountResult
{
    Created,
    DuplicateEmail
}

// SQLite account storage. Schema changes are applied in order using PRAGMA user_version.
internal sealed class AccountStore
{
    private const int SchemaVersion = 1;
    private const int SqliteConstraint = 19;
    private const int SqliteConstraintUnique = 2067;
    private readonly string _connectionString;

    public AccountStore(IOptions<MatchmakingOptions> options, IHostEnvironment environment)
    {
        if (string.IsNullOrWhiteSpace(options.Value.DatabasePath))
            throw new InvalidOperationException("Matchmaking:DatabasePath is required.");
        DatabasePath = Path.Combine(environment.ContentRootPath, options.Value.DatabasePath);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = 30
        }.ToString();
    }

    internal string DatabasePath { get; }

    internal void Initialize()
    {
        var directory = Path.GetDirectoryName(DatabasePath);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using (var journal = connection.CreateCommand())
        {
            journal.CommandText = "PRAGMA journal_mode = WAL;";
            journal.ExecuteNonQuery();
        }

        using var transaction = connection.BeginTransaction();
        using var versionCommand = connection.CreateCommand();
        versionCommand.Transaction = transaction;
        versionCommand.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(versionCommand.ExecuteScalar());
        if (version > SchemaVersion)
            throw new InvalidOperationException($"The account database schema version {version} is newer than this service supports ({SchemaVersion}).");

        if (version < 1)
        {
            using var create = connection.CreateCommand();
            create.Transaction = transaction;
            create.CommandText = """
                CREATE TABLE accounts (
                    player_id TEXT NOT NULL PRIMARY KEY,
                    email_normalized TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                PRAGMA user_version = 1;
                """;
            create.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    internal async Task<CreateAccountResult> CreateAsync(AccountRecord account, DateTimeOffset createdAtUtc, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO accounts (player_id, email_normalized, password_hash, created_at_utc)
            VALUES ($playerId, $email, $passwordHash, $createdAtUtc);
            """;
        command.Parameters.AddWithValue("$playerId", account.PlayerId.ToString("D"));
        command.Parameters.AddWithValue("$email", account.NormalizedEmail);
        command.Parameters.AddWithValue("$passwordHash", account.PasswordHash);
        command.Parameters.AddWithValue("$createdAtUtc", createdAtUtc.UtcDateTime.ToString("O"));
        try
        {
            await command.ExecuteNonQueryAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CreateAccountResult.Created;
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == SqliteConstraint &&
                                                 exception.SqliteExtendedErrorCode == SqliteConstraintUnique)
        {
            return CreateAccountResult.DuplicateEmail;
        }
    }

    internal async Task<AccountRecord?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT player_id, password_hash FROM accounts WHERE email_normalized = $email;";
        command.Parameters.AddWithValue("$email", normalizedEmail);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new AccountRecord(Guid.ParseExact(reader.GetString(0), "D"), normalizedEmail, reader.GetString(1));
    }

    internal async Task UpdatePasswordHashAsync(Guid playerId, string passwordHash, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE accounts SET password_hash = $passwordHash WHERE player_id = $playerId;";
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$playerId", playerId.ToString("D"));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
