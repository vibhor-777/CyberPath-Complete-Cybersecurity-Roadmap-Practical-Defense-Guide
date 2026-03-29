# K — Kerberos

## Beginner Explanation
Kerberos is the authentication protocol used in Active Directory environments. Named after the three-headed dog guarding the underworld, Kerberos involves three parties: the client, the server, and a trusted Key Distribution Center (KDC). Instead of sending passwords over the network, Kerberos issues encrypted tickets — like theme park wristbands that prove you've paid, without showing your wallet at every ride.

## Technical Deep Dive
### The Kerberos Authentication Flow
```
1. AS-REQ:  Client → KDC: "I am Alice" + timestamp encrypted with Alice's key hash
2. AS-REP:  KDC → Client: TGT (Ticket Granting Ticket) encrypted with KDC secret
                           + Session Key encrypted with Alice's key
3. TGS-REQ: Client → KDC: TGT + "I want to access File Server"
4. TGS-REP: KDC → Client: Service Ticket encrypted with File Server's key
5. AP-REQ:  Client → File Server: Service Ticket
6. AP-REP:  File Server → Client: Confirmation
```

### Kerberoasting (Attack — for Defensive Awareness)
Service accounts with SPNs have their tickets encrypted with the service account's password hash. Attackers request these tickets and crack them offline.
**Defense:**
- Use long, random service account passwords (25+ chars) — managed service accounts (gMSA) do this automatically
- Monitor for Event ID 4769 (Kerberos service ticket request) with unusual requestors
- Use AES encryption for service tickets (not RC4)

### Pass-the-Ticket (Attack — for Defensive Awareness)
Stolen Kerberos tickets can be used directly without knowing the password.
**Defense:**
- Enable Credential Guard (prevents ticket theft from memory)
- Short ticket lifetimes (default 10 hours; consider shorter for privileged accounts)
- Monitor for tickets being used from unusual source IPs

### Golden Ticket (Attack — for Defensive Awareness)
If KRBTGT account hash is stolen, attacker can forge any ticket for any user indefinitely.
**Defense:**
- Rotate KRBTGT password twice (invalidates existing golden tickets)
- Restrict Domain Controller access
- Monitor for impossible Kerberos ticket properties (unusual PAC attributes)

## Real-World Relevance
The **NotPetya (2017)** worm used Mimikatz to steal Kerberos tickets from memory, enabling lateral movement across entire enterprise networks without any password brute-forcing — pure ticket-based lateral movement.

## Defensive Measures
1. Deploy Credential Guard on all Windows 10/Server 2016+ systems
2. Use Group Managed Service Accounts (gMSA) for all service accounts
3. Enable AES Kerberos encryption (disable RC4)
4. Monitor Event ID 4769 for unusual service ticket requests
5. Alert on KRBTGT password age > 180 days

## Practice Challenge
In a lab AD environment: Query all SPNs to identify Kerberoastable accounts: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`. Identify which accounts have weak passwords and should use gMSA instead.
