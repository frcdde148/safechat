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
server-side admin APIs. It no longer opens SQLite database files directly.

Implemented console pages:

- `Online / Mute`: online contacts, mute/unmute, and kick online users through ChatServer.
- `Users / Roles`: update user/admin roles through AS and ChatServer admin APIs.
- `Tickets / Sessions`: inspect AS active sessions and invalidate sessions through AS.
- `IP Bans`: create temporary IP bans through AS.
- `Chat Records`: query traceable chat history through ChatServer.
- `Audit Logs`: query and export AS/TGS/ChatServer audit logs through each server.
- `Service Status`: check configured service endpoints and database paths.

Operational note: the console uses the administrator password only for the
normal Kerberos login. It then sends `AS_ADMIN_TOKEN_REQ` with the existing
TGT and authenticator. AS returns a signed, time-limited `admin_token`; later
AS/TGS admin requests carry only that token. ChatServer admin APIs continue to
verify the Kerberos service ticket, request signature, and admin role.

Before using it on an existing deployment, initialize or migrate the AS and
ChatServer databases so the `admin` user and `mute_rules` table exist:

```powershell
python -m database.init_db --role as
python -m database.init_db --role tgs
python -m database.init_db --role chat
```
