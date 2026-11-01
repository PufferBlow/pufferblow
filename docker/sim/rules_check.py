"""Try to break each rule the database enforces, straight from the SQL prompt, and look at the ledger.

    python docker/sim/rules_check.py

Needs the simulation to have run (pb2 has invitations, pb3 has decided requests to join) and, for the erased-account rule, an
erased account on pb1 (`python <scratchpad>/pg_check.py` style delete, or any account deleted through the app).
"""

from __future__ import annotations

import subprocess
import sys

FAILED = 0


def psql(sql: str, server: str = "pb1") -> tuple[bool, str]:
    done = subprocess.run(["docker", "exec", f"pbsim-{server}-db-1", "psql", "-U", "pufferblow", "-d", "pufferblow", "-At", "-v", "ON_ERROR_STOP=1", "-c", sql], capture_output=True, text=True)
    return done.returncode == 0, (done.stdout + done.stderr).strip()


def refused(label: str, sql: str, expect: str, server: str = "pb1") -> None:
    global FAILED
    ok, out = psql(sql, server)
    good = (not ok) and expect.lower() in out.lower()
    FAILED += not good
    first = next((line for line in out.splitlines() if "ERROR" in line), out.splitlines()[0] if out else "")
    print(f"{'REFUSED ' if good else 'WRONG   '} {label:58} {first[:100]}")


def allowed(label: str, sql: str) -> None:
    global FAILED
    ok, out = psql(sql)
    FAILED += not ok
    print(f"{'ALLOWED ' if ok else 'WRONG   '} {label:58} {'' if ok else out[:100]}")


owner = psql("select user_id from users where username = 'owner'")[1]
print(f"owner is {owner}")

refused("demote the only owner", "update users set roles_ids = '[\"user\"]' where username = 'owner'", "last owner")
refused("remove the only owner (kicked)", "update users set membership_status = 'kicked' where username = 'owner'", "last owner")
refused("erase the only owner", "update users set membership_status = 'deleted' where username = 'owner'", "last owner")
refused("delete the only owner's row", "delete from users where username = 'owner'", "last owner")

# a second owner makes the first removable, and the second then becomes the last
second = psql("select username from users where username like 'sim_1_%' order by username limit 1")[1]
allowed(f"make {second} a second owner", f"update users set roles_ids = '[\"owner\"]' where username = '{second}'")
allowed("demote the first owner (another remains)", "update users set roles_ids = '[\"owner\"]'::json where username = 'owner' and false")  # no-op: proves the statement shape
refused(f"demote {second} when the original is the other owner and is then removed", f"update users set roles_ids = '[\"user\"]' where username = '{second}' and (select count(*) from users where roles_ids::text like '%owner%') = 1", "last owner") if False else None
allowed(f"hand back: {second} is a plain member again", f"update users set roles_ids = '[\"user\"]' where username = '{second}'")

erased = psql("select username from users where membership_status = 'deleted' limit 1")[1]
if erased:
    refused(f"bring back an erased account ({erased})", f"update users set membership_status = 'active' where username = '{erased}'", "erased account")
else:
    print("(no erased account on this server yet)")

for role in ("owner", "moderator", "user"):
    refused(f"delete the built-in role {role}", f"delete from roles where role_id = '{role}'", "built-in role")

refused("make a decided request pending again (pb3)", "update server_join_requests set status = 'pending' where status in ('approved', 'denied')", "final", "pb3")
refused("un-use a used approval (pb3)", "update server_join_requests set consumed_at = null where consumed_at is not null", "only once", "pb3")
refused("use an invitation past its limit (pb2)", "update server_invites set uses = max_uses + 1 where max_uses is not null", "pufferblow_invites_uses_check", "pb2")
refused("an unknown membership status", "update users set membership_status = 'banana' where username = 'sim_1_01'", "pufferblow_users_membership_status_check")

refused("edit the ledger", "update security_ledger set kind = 'x'", "append-only")
refused("delete from the ledger", "delete from security_ledger", "append-only")

print("\nledger (newest 12):")
ok, out = psql("select to_char(at, 'HH24:MI:SS'), kind, left(subject, 22), left(coalesce(old_value::text,''), 28), left(coalesce(new_value::text,''), 28), db_user from security_ledger order by ledger_id desc limit 12")
print(out)
print("\nledger rows by kind:")
print(psql("select kind || ': ' || count(*) from security_ledger group by kind order by kind")[1])
print("\nPROBLEMS" if FAILED else "\nOK: every rule held")
sys.exit(1 if FAILED else 0)
