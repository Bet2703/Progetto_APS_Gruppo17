import os
import time
import json
import random
from typing import List, Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto_core import CryptoEngine, MerkleTree

class BulletinBoard: 
    def __init__(self):
        self.records: List[Dict[str, Any]] = []
        self.checkpoints: List[Dict[str, Any]] = []
        self.partial_results: List[Dict[str, Any]] = []
        self.final_result: Dict[str, Any] = {}
        self.pk_AE = None
        self.pk_RE = None
        self.L: List[str] = []
        self.date: str = ""

class RegistroElettorale:
    # Gestisce l'identità degli utenti (Fase di autenticazione e rilascio Token anonimi)
    def __init__(self):
        self.sk_RE = rsa.generate_private_key(65537, 2048)
        self.pk_RE = self.sk_RE.public_key()
        self.RE_DB, self.issued_tokens, self.challenges = {}, {}, {}

    def register_condomino(self, id_i: str, k_i: bytes):
        # Fase di Enrollment (Fuori banda)
        self.RE_DB[id_i], self.issued_tokens[id_i] = k_i, False

    def receive_request(self, id_i: str) -> bytes:
        if id_i not in self.RE_DB or self.issued_tokens[id_i]: 
            raise ValueError("Non autorizzato o token già emesso.")
        nonce_re = os.urandom(16)
        self.challenges[id_i] = nonce_re
        return nonce_re

    def process_response(self, id_i: str, iv: bytes, response_cipher: bytes) -> Tuple[bytes, bytes]:
        decrypted = CryptoEngine.aes_decrypt_cbc(self.RE_DB[id_i], iv, response_cipher)
        if decrypted[:16] != self.challenges[id_i] or decrypted[16:].decode() != id_i:
            raise PermissionError("Handshake Fallito.")
        
        # Rilascio del token anonimo tau_i firmato asimmetricamente in RSA-PSS
        tau_i = os.urandom(16)
        sigma_tau = CryptoEngine.rsa_sign_pss(self.sk_RE, tau_i)
        self.issued_tokens[id_i] = True
        return tau_i, sigma_tau

class AutoritaElettorale:
    # Gestisce la ricezione delle schede cifrate e lo scrutinio anonimo a batch
    def __init__(self, k_anonimato: int, pk_RE: rsa.RSAPublicKey, bb: BulletinBoard):
        self.k = k_anonimato
        self.pk_RE = pk_RE
        self.bb = bb
        self.sk_AE = rsa.generate_private_key(65537, 2048)
        self.pk_AE = self.sk_AE.public_key()
        self.used_tokens, self.merkle_tree, self.pad = {}, MerkleTree(), b'\x00'*32
        self.current_batch_index = 0

    def receive_vote(self, M_i: Dict[str, Any]) -> List[Tuple[bytes, str]]:
        tau_i, sigma, h_i = M_i["tau_i"], M_i["sigma_tau_i"], M_i["h_i"]
        # Verifica firma RE sul token per bloccare attacchi di Double-Voting
        if not CryptoEngine.rsa_verify_pss(self.pk_RE, sigma, tau_i) or tau_i in self.used_tokens:
            return None
        
        self.used_tokens[tau_i] = True
        idx = len(self.bb.records)
        
        self.bb.records.append({
            "C_i": M_i["C_i"], 
            "tau_i": tau_i, 
            "sigma_tau_i": sigma,
            "h_i": h_i, 
            "Omega_i": self.pad, # Inizializzato col pad nullo noto a tutti
            "voto_chiaro": None,
            "r_chiaro": None
        })

        # Generazione foglia con separatore di dominio b'\x00' per l'albero di Merkle
        current_leaves = [CryptoEngine.hash_sha256(b'\x00' + r["tau_i"] + r["h_i"] + r["Omega_i"]) for r in self.bb.records]
        self.merkle_tree.build_tree(current_leaves)
        proof_pi = self.merkle_tree.get_proof(idx)

        # Rilascio Checkpoint periodico ogni k voti ricevuti
        if (idx + 1) % self.k == 0:
            root = self.merkle_tree.get_root()
            j = (idx + 1) // self.k
            ts = str(int(time.time())).encode()
            sigma_root = CryptoEngine.rsa_sign_pss(self.sk_AE, root + str(j).encode() + ts)
            self.bb.checkpoints.append({"root_j": root, "j": j, "timestamp": ts, "sigma_root_j": sigma_root})
            
        return proof_pi

    def scrutina_singolo_batch(self, logger=None) -> Tuple[int, int, bool, List[int]]:
        n = len(self.bb.records)
        start = self.current_batch_index * self.k
        end = min(start + self.k, n)
        
        if start >= n:
            return start, end, True, []

        indices = list(range(start, end))
        shuffled_indices = indices[:]
        # Shuffling deterministico del batch per spezzare la tracciabilità temporale dei voti (K-Anonymity)
        random.shuffle(shuffled_indices)
        
        for idx in shuffled_indices:
            r = self.bb.records[idx]
            iv, c_prime, c_k = r["C_i"]
            # Decifratura della chiave di sessione (RSA-OAEP) e del payload (AES-CBC)
            k_sess = CryptoEngine.rsa_decrypt_oaep(self.sk_AE, c_k)
            v_bytes = CryptoEngine.aes_decrypt_cbc(k_sess, iv, c_prime)
            
            # Controllo vincolo di integrità: l'hash deve coincidere con il commitment iniziale h_i
            h_calcolato = CryptoEngine.hash_sha256(v_bytes)
            if h_calcolato == r["h_i"]:
                r["voto_chiaro"], r["Omega_i"] = v_bytes[0], r["h_i"]
                r["r_chiaro"] = v_bytes[17:]
                if logger:
                    logger(f"   ↳ [CONTR_INT] Riga BB[{idx}]: SHA-256(V_j) [{h_calcolato.hex()[:12]}...] == h_j [{r['h_i'].hex()[:12]}...] -> Esito: MATEMATICAMENTE VALIDO")
            else:
                r["voto_chiaro"], r["Omega_i"] = "ANNULLATA", CryptoEngine.hash_sha256(b"ANNULLATA")
                if logger:
                    logger(f"   ↳ [CONTR_INT] Riga BB[{idx}]: SHA-256(V_j) [{h_calcolato.hex()[:12]}...] != h_j [{r['h_i'].hex()[:12]}...] -> Esito: CORROTTO/ANNULLATA")

        # Ricostruzione dell'albero Merkle post-scrutinio con le foglie aggiornate (Omega_i sostituito al pad)
        leaves = [CryptoEngine.hash_sha256(b'\x00' + rec["tau_i"] + rec["h_i"] + rec["Omega_i"]) for rec in self.bb.records]
        self.merkle_tree.build_tree(leaves)
        root_b = self.merkle_tree.get_root()
        
        p_data = f"batch_{self.current_batch_index}_range_{start}-{end}_root_{root_b.hex()}".encode()
        sigma_b = CryptoEngine.rsa_sign_pss(self.sk_AE, CryptoEngine.hash_sha256(p_data))
        self.bb.partial_results.append({"batch_id": self.current_batch_index, "merkle_root": root_b, "sigma_b": sigma_b, "serialized_data": p_data})

        self.current_batch_index += 1
        all_done = (self.current_batch_index * self.k >= n)

        if all_done:
            self.computa_risultato_finale()

        return start, end, all_done, shuffled_indices

    def computa_risultato_finale(self):
        conteggio = {}
        for r in self.bb.records:
            if isinstance(r["voto_chiaro"], int): 
                conteggio[r["voto_chiaro"]] = conteggio.get(r["voto_chiaro"], 0) + 1
        r_json = json.dumps(conteggio, sort_keys=True).encode()
        sigma_R = CryptoEngine.rsa_sign_pss(self.sk_AE, CryptoEngine.hash_sha256(r_json))
        
        self.bb.final_result = {
            "Risultato_Finale": "Scrutinio Completato", 
            "R_final": conteggio, 
            "sigma_R_final": sigma_R, 
            "raw_json": r_json
        }

class Elettore:
    # Client locale del condomino
    def __init__(self, id_i: str, k_i: bytes):
        self.id_i, self.k_i = id_i, k_i
        self.tau_i, self.sigma_tau_i, self.r_i, self.voto, self.h_i = None, None, None, None, None
        self.pi_i = None

    def esegui_handshake(self, re: RegistroElettorale):
        nonce_re = re.receive_request(self.id_i)
        iv, cipher = CryptoEngine.aes_encrypt_cbc(self.k_i, nonce_re + self.id_i.encode())
        self.tau_i, self.sigma_tau_i = re.process_response(self.id_i, iv, cipher)

    def voto_e_prepara(self, cand: int, ae: AutoritaElettorale):
        # Generazione della stringa di voto localmente blindata: V_i = c_i || tau_i || r_i
        self.voto, self.r_i = cand, os.urandom(16)
        v_i = bytes([cand]) + self.tau_i + self.r_i
        self.h_i = CryptoEngine.hash_sha256(v_i)
        
        # Pipeline di Cifratura Ibrida (AES-CBC per il messaggio, RSA-OAEP per la chiave)
        k_sess = os.urandom(32)
        iv, c_prime = CryptoEngine.aes_encrypt_cbc(k_sess, v_i)
        c_k = CryptoEngine.rsa_encrypt_oaep(ae.pk_AE, k_sess)
        
        M_i = {"C_i": (iv, c_prime, c_k), "tau_i": self.tau_i, "sigma_tau_i": self.sigma_tau_i, "h_i": self.h_i}
        self.pi_i = ae.receive_vote(M_i)