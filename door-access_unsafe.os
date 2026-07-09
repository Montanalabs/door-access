#! VULNERABLE door-access — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant unlockDoor irreversible confidence 70

let raw = fetch<web>
commit { unlockDoor(raw) }  # tainted -> tool: REJECTED
