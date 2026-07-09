#! Door-access agent — untrusted a credential can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires unlockDoor — the door-access agent sink
#! @effect io
#! @confidence 70
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant unlockDoor irreversible confidence 70

type Door = FrontDoor | Garage | Office
type Decision = Unlock(Door) | Deny

let raw = fetch<web>  # UNTRUSTED a credential — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
commit { unlockDoor(d) }  # act on the trusted decision only
