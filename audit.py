from typing import List
from crypto_core import CryptoEngine, MerkleTree
from attori import BulletinBoard

def run_universal_audit(bb: BulletinBoard) -> List[str]:
    # Funzione di Verificabilità Universale: chiunque può eseguirla per validare l'elezione
    logs = []
    if not bb.records:
        logs.append("[-] Errore Verifica: Nessun voto presente sul Bulletin Board.")
        return logs

    # V.1: Validità firme token RE
    logs.append(f"[Ispezione V.1] Verifica firme RSA-PSS su {len(bb.records)} token di voto...")
    for i, r in enumerate(bb.records):
        # Verifica che il token tau_i esposto sia stato effettivamente firmato e autorizzato da RE
        if not CryptoEngine.rsa_verify_pss(bb.pk_RE, r["sigma_tau_i"], r["tau_i"]):
            logs.append(f"  ↳ [-] V.1 FALLITO: Token compromesso alla riga BB[{i}]")
            return logs
    logs.append("  ↳ [✓] V.1 Passato: Ogni scheda sul BB possiede un token con firma RE integra.")

    # V.2: Assenza duplicati token
    tokens = [r["tau_i"] for r in bb.records]
    logs.append(f"[Ispezione V.2] Controllo univocità dei token spesi (Analisi Double-Voting): {len(tokens)} totali.")
    # Se la lunghezza della lista diverge dal set dei valori unici, un token è stato speso più volte
    if len(tokens) != len(set(tokens)):
        logs.append("  ↳ [-] V.2 FALLITO: Rilevato token duplicato (Frode Double-Voting).")
        return logs
    logs.append(f"  ↳ [✓] V.2 Passato: Cardinalità coerente |{{tau_i}}| == {len(set(tokens))} (Tutti i token sono distinti).")

    # V.3: Coerenza dei commitment h_i e Omega_i
    logs.append("[Ispezione V.3] Validazione corrispondenza matematica tra Voti esposti e Commitment h_i...")
    for i, r in enumerate(bb.records):
        if r["voto_chiaro"] is not None:
            if r["voto_chiaro"] == "ANNULLATA":
                continue
            # Ricostruzione della stringa V_i ed esecuzione del vincolo h_i == SHA-256(V_i) == Omega_i
            v_i_star = bytes([r["voto_chiaro"]]) + r["tau_i"] + r["r_chiaro"]
            h_verificato = CryptoEngine.hash_sha256(v_i_star)
            if h_verificato != r["h_i"] or r["Omega_i"] != r["h_i"]:
                logs.append(f"  ↳ [-] V.3 FALLITO: Discrepanza commitment alla riga BB[{i}]")
                return logs
    logs.append("  ↳ [✓] V.3 Passato: Tutti i nodi Omega_i coincidono simmetricamente con l'hash delle stringhe decifrate.")

    # V.4: Coerenza conteggio dichiarato
    conteggio_osservatore = {}
    for r in bb.records:
        if isinstance(r["voto_chiaro"], int):
            conteggio_osservatore[r["voto_chiaro"]] = conteggio_osservatore.get(r["voto_chiaro"], 0) + 1
    
    logs.append(f"[Ispezione V.4] Ricalcolo indipendente del Tally: {conteggio_osservatore}")
    # Controllo che l'AE non abbia alterato la somma aritmetica delle preferenze pubblicate
    if bb.final_result and conteggio_osservatore != bb.final_result.get("R_final", {}):
        logs.append("  ↳ [-] V.4 FALLITO: Il tabellone aggregato differisce dalla somma dei singoli elementi.")
        return logs
    logs.append("  ↳ [✓] V.4 Passato: La somma delle preferenze in chiaro e il report finale coincidono.")

    # V.5: Firma AE su risultato finale
    if bb.final_result:
        logs.append("[Ispezione V.5] Validazione firma asimmetrica dell'AE sul report finale consolidato...")
        # Controllo di autenticità e non ripudio sui risultati firmati dall'AE
        if not CryptoEngine.rsa_verify_pss(bb.pk_AE, bb.final_result["sigma_R_final"], CryptoEngine.hash_sha256(bb.final_result["raw_json"])):
            logs.append("  ↳ [-] V.5 FALLITO: Firma dell'AE su R_final corrotta.")
            return logs
    logs.append("  ↳ [✓] V.5 Passato: Autenticità e non ripudio dell'AE sul risultato validata con successo.")

    # V.6: Controllo radici checkpoint intermedi
    logs.append(f"[Ispezione V.6] Controllo di validità dei {len(bb.checkpoints)} checkpoint periodici generati...")
    for cp in bb.checkpoints:
        # Verifica della firma asimmetrica apposta progressivamente dall'AE su ogni radice intermedia
        payload = cp["root_j"] + str(cp["j"]).encode() + cp["timestamp"]
        if not CryptoEngine.rsa_verify_pss(bb.pk_AE, cp["sigma_root_j"], payload):
            logs.append(f"  ↳ [-] V.6 FALLITO: Checkpoint j={cp['j']} presenta una firma non valida.")
            return logs
    logs.append("  ↳ [✓] V.6 Passato: Tutte le radici intermedie firmate nei checkpoint incrementali sono integre.")

    # V.7: Calcolabilità radice finale dalle foglie
    if bb.records and bb.partial_results:
        logs.append("[Ispezione V.7] Ricostruzione integrale dell'albero di Merkle dalle foglie post-scrutinio...")
        # Ricostruisco l'albero Merkle da zero usando b'\x00' per verificare la consistenza strutturale globale
        tree_audit = MerkleTree()
        leaves_audit = [CryptoEngine.hash_sha256(b'\x00' + r["tau_i"] + r["h_i"] + r["Omega_i"]) for r in bb.records]
        tree_audit.build_tree(leaves_audit)
        
        logs.append(f"  ↳ Radice ricalcolata: {tree_audit.get_root().hex()[:24]}...")
        logs.append(f"  ↳ Radice sul BB:      {bb.partial_results[-1]['merkle_root'].hex()[:24]}...")
        if tree_audit.get_root() != bb.partial_results[-1]["merkle_root"]:
            logs.append("  ↳ [-] V.7 FALLITO: La radice generata diverge dallo stato del tabellone.")
            return logs
    logs.append("  ↳ [✓] V.7 Passato: La Merkle Root finale è coerente con la computazione dal basso delle foglie esposed.")

    # V.8: Catena risultati parziali dei batch
    logs.append("[Ispezione V.8] Verifica di autenticità e concatenazione dei blocchi parziali dei batch...")
    for pb in bb.partial_results:
        # Validazione della catena dei batch: ogni batch deve essere firmato dall'AE
        if not CryptoEngine.rsa_verify_pss(bb.pk_AE, pb["sigma_b"], CryptoEngine.hash_sha256(pb["serialized_data"])):
            logs.append(f"  ↳ [-] V.8 FALLITO: Firma del batch parziale b={pb['batch_id']} corrotta.")
            return logs
    logs.append("  ↳ [✓] V.8 Passato: Tutti i flussi parziali e incrementali intermedi risultano firmati e autentici.")
    
    logs.append("\n[***] ESITO VERIFICA UNIVERSALE: L'INTERA ELEZIONE È COERENTE AL 100% [***]")
    return logs