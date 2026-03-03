
### MoxGuard — Nicotine+ Chat moderation plugin ###
# Handles trolls, racists, spammers, redditors and general chat-ruinerunenjoyerers.
# Instructions written on Arch, please check your Nicotine install directory yourself. Find the plugins folder and chuck it in there.
# In nicotine, go to preferences, plugins, add plugins. Assuming you've placed the files in the correct directory, you should see Moxguard.



# Detection layers:
#   1. Bad phrase / keyword matching (configurable list, you choose what offends you)
#   2. Flood detection (too many messages in a rolling window - gtfo)
#   3. ASCII / character spam (same char repeated -ever wonder who messes up public bathrooms? These guys)
#   4. ALL CAPS shouting - stfu already
#   5. Multi-nick detection (same IP, different username - nored)
#
# Actions:
#   - Zap (silently drop) offending messages. They wont even know you are noring them. They just shout into /dev/null.
#   - Log every violation with IP + country - not that it means anything. But you know, MAGA
#   - Auto-ignore users after reaching the warn threshold
#   - Taint IPs of ignored users → auto-ignore any new nick from that IP
#   - Whitelist trusted users to never filter

 
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
 │ ✅ Already ignored │ Nores their messages even if Nicotine+ would let them through │
 └────────────────────┴──────────────────────────────────────────────────────────────┘

 All detection layers apply to both rooms and PMs.

 ────────────────────────────────────────────────────────────────────────────────

 Commands (type in any chat window):

 ```
   /mg status                — who's been flagged, counts, settings
   /mg ignore <user>         — manual instant ignore
   /mg unignore <user>       — undo
   /mg whitelist <user>      — never filter this person
   /mg unwhitelist <user>    - on second thoughts
   /mg clear <user>          — reset their violation count
   /mg reload                — recompile phrase list after you edit it in settings
   /mg ipinfo <user>    — IP, country, tainted status, all seen altnicks
   /mg altnicks <user>  — list every nick seen from the same IP
   /mg status           — now includes tainted IP count + altnicks per offender
 ```

 ────────────────────────────────────────────────────────────────────────────────

 Tweaking the word list: Go to Preferences → Plugins → MoxGuard settings. Add/remove phrases there
 — no restart needed, just /mg reload after saving.

 Violation log lands at: ~/.local/share/nicotine/moxguard  (configurable in Moxguard settings)
 .logIP Stats — every violation now includes IP + country in the log. When the resolution comes back
 from the server (async), it updates the log entry. If a user has violations when their IP
 resolves, it logs the full picture.

 Multi-nick detection — as soon as someone is ignored, their IP gets tainted. When any new username
 resolves to a tainted IP:
 - MoxGuard logs a [MULTI-NICK] alert with the known bad nicks linked to that IP
 - Auto-ignores the new nick immediately
 - Works even if they join a room silently without saying anything — the
 user_join_chatroom_notification hook proactively requests IPs for everyone who walks into a room
 you're in

 ────────────────────────────────────────────────────────────────────────────────




 


 Example log output:

 ```
   [VIOLATION #1] user=racist123 [45.33.32.156 | US] room:jazz reason=bad_phrase:'kike' msg='...'
   [IGNORED] racist123 [45.33.32.156 | US] — reason: bad_phrase:'kike'
   [IP-TAINT] racist123 → 45.33.32.156 added to tainted list
   [MULTI-NICK] hater456 [45.33.32.156 | US] matches tainted IP — known bad nicks: ['racist123']
   [IGNORED] hater456 [45.33.32.156 | US] — reason: multi_nick|ip:45.33.32.156|same_ as:racist123
 ```

 Reload the plugin in Preferences → Plugins → MoxGuard.














 ```
   1. Unzip into ~/.local/share/nicotine/plugins/mox_guard/
   2. Open Nicotine+ → Preferences → Plugins
   3. Enable MoxGuard
   4. Done
