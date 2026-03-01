


 
 What it does:

 ┌────────────────────┬──────────────────────────────────────────────────────────────┐
 │ Layer              │ What it catches                                              │
 ├────────────────────┼──────────────────────────────────────────────────────────────┤
 │ 🔤 Phrase match    │ Racial slurs, hate speech, shock content — configurable list │
 ├────────────────────┼──────────────────────────────────────────────────────────────┤
 │ 💥 Flood detection │ >8 messages in 20 seconds (adjustable)                       │
 ├────────────────────┼──────────────────────────────────────────────────────────────┤
 │ 🔡 Char spam       │ AAAAAAAAAAA type garbage                                     │
 ├────────────────────┼──────────────────────────────────────────────────────────────┤
 │ 📢 ALL CAPS        │ Long messages that are 80%+ uppercase                        │
 ├────────────────────┼──────────────────────────────────────────────────────────────┤
 │ ✅ Already ignored │ Zaps their messages even if Nicotine+ would let them through │
 └────────────────────┴──────────────────────────────────────────────────────────────┘

 All detection layers apply to both rooms and PMs.

 ────────────────────────────────────────────────────────────────────────────────

 Commands (type in any chat window):

 ```
   /mg status                — who's been flagged, counts, settings
   /mg ignore <user>         — manual instant ignore
   /mg unignore <user>       — undo
   /mg whitelist <user>      — never filter this person
   /mg unwhitelist <user>
   /mg clear <user>          — reset their violation count
   /mg reload                — recompile phrase list after you edit it in settings
 ```

 ────────────────────────────────────────────────────────────────────────────────

 Tweaking the word list: Go to Preferences → Plugins → MoxGuard settings. Add/remove phrases there
 — no restart needed, just /mg reload after saving.

 Violation log lands at: ~/.local/share/nicotine/moxguard.logIP Stats — every violation now includes IP + country in the log. When the resolution comes back
 from the server (async), it updates the log entry. If a user has violations when their IP
 resolves, it logs the full picture.

 Multi-nick detection — as soon as someone is ignored, their IP gets tainted. When any new username
 resolves to a tainted IP:
 - MoxGuard logs a [MULTI-NICK] alert with the known bad nicks linked to that IP
 - Auto-ignores the new nick immediately
 - Works even if they join a room silently without saying anything — the
 user_join_chatroom_notification  hook proactively requests IPs for everyone who walks into a room
 you're in

 ────────────────────────────────────────────────────────────────────────────────

 New commands:

 ```
   /mg ipinfo <user>    — IP, country, tainted status, all seen altnicks
   /mg altnicks <user>  — list every nick seen from the same IP
   /mg status           — now includes tainted IP count + altnicks per offender
 ```

 Example log output:

 ```
   [VIOLATION #1] user=racist123 [45.33.32.156 | US] room:jazz reason=bad_phrase:'kike' msg='...'
   [IGNORED] racist123 [45.33.32.156 | US] — reason: bad_phrase:'kike'
   [IP-TAINT] racist123 → 45.33.32.156 added to tainted list
   [MULTI-NICK] hater456 [45.33.32.156 | US] matches tainted IP — known bad nicks: ['racist123']
   [IGNORED] hater456 [45.33.32.156 | US] — reason: multi_nick|ip:45.33.32.156|same_ as:racist123
 ```

 Reload the plugin in Preferences → Plugins → MoxGuard (untick/tick) to pick up the new version.














 ```
   1. Unzip into ~/.local/share/nicotine/plugins/mox_guard/
   2. Open Nicotine+ → Preferences → Plugins
   3. Enable MoxGuard
   4. Done
