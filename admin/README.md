# SafeChat Admin Console

Run the standalone administrator console:

```powershell
python -m admin.main
```

Default administrator account after database initialization:

```text
admin / admin123
```

The console uses Kerberos authentication through AS/TGS/ChatServer, then calls
ChatServer admin APIs for mute/unmute operations. Chat records and audit logs
are queried read-only from the SQLite database paths in `settings.json`.

Implemented console pages:

- `Online / Mute`: online contacts, mute/unmute, and kick online users.
- `Users / Roles`: update user/admin roles in AS and ChatServer databases.
- `Tickets / Sessions`: inspect AS active sessions, invalidate sessions, and kick users online.
- `IP Bans`: write temporary IP bans to the AS database.
- `Chat Records`: query traceable chat history from ChatServer database.
- `Audit Logs`: query and export AS/TGS/ChatServer audit logs as CSV.
- `Service Status`: check configured service endpoints and database paths.

Operational note: role management, IP bans, and AS session invalidation write to
the SQLite database paths configured in `settings.json`. In a four-host
deployment, run the admin console on a machine that can access those database
files, or replace those actions with remote AS/TGS admin APIs later.

Before using it on an existing deployment, initialize or migrate the AS and
ChatServer databases so the `admin` user and `mute_rules` table exist:

```powershell
python -m database.init_db --role as
python -m database.init_db --role chat
```
