import os
from typing import List, Tuple
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoEngine:
    # Motore crittografico centralizzato: racchiude tutte le primitive simmetriche e asimmetriche
    
    @staticmethod
    def hash_sha256(data: bytes) -> bytes:
        # Funzione di hashing SHA-256 standard utilizzata per i commitment e i nodi del Merkle Tree
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def aes_encrypt_cbc(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        # Generazione dell'Inizializzazione Vector (IV) per la modalità CBC
        iv = os.urandom(16)
        # AES lavora su blocchi rigidi di 128 bit. Il padding PKCS7 permette di allineare i dati
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        # Inizializzazione della cifratura simmetrica AES-256
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        return iv, cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()

    @staticmethod
    def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        # Decifratura in modalità CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        padded_data = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
        # Rimozione del padding PKCS7 per recuperare l'esatta stringa in chiaro originaria
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    @staticmethod
    def rsa_encrypt_oaep(pub_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
        # Cifratura asimmetrica della chiave di sessione (Cifratura Ibrida).
        # OAEP con SHA-256 
        return pub_key.encrypt(
            plaintext, 
            asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    @staticmethod
    def rsa_decrypt_oaep(priv_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        # Decifratura asimmetrica della chiave di sessione AES da parte dell'AE
        return priv_key.decrypt(
            ciphertext, 
            asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    @staticmethod
    def rsa_sign_pss(priv_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        # Firma digitale asimmetrica. PSS introduce un salt casuale rendendo la firma non deterministica
        return priv_key.sign(
            data, 
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), 
            hashes.SHA256()
        )

    @staticmethod
    def rsa_verify_pss(pub_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
        # Verifica pubblica della firma. Se la firma è matematicamente integra restituisce True,
        # intercetta l'eccezione crittografica in caso di manomissione dei dati e restituisce False
        try:
            pub_key.verify(
                signature, 
                data, 
                asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), 
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

class MerkleTree:
    # Struttura dati ad albero binario per garantire l'integrità e l'inclusione logaritmica dei record
    def __init__(self):
        self.leaves_hashes: List[bytes] = [] # Array delle foglie iniziali (livello 0)
        self.tree_levels: List[List[bytes]] = [] # Matrice contenente tutti i livelli calcolati dell'albero

    def build_tree(self, current_leaves: List[bytes]):
        self.leaves_hashes = current_leaves[:]
        if not self.leaves_hashes: 
            return
        leaves = self.leaves_hashes[:]
        
        while (len(leaves) & (len(leaves) - 1)) != 0 or len(leaves) == 0:
            leaves.append(leaves[-1] if leaves else b'\x00'*32)
            
        levels = [leaves]
        # Ciclo di risalita combinata: accoppio i nodi a due a due finché non arrivo alla singola radice (Root)
        while len(levels[-1]) > 1:
            curr = levels[-1]
            # SEPARAZIONE DI DOMINIO: si antepone il byte b'\x01' alla concatenazione dei nodi interni.
            # Ciò impedisce confondere un nodo interno per foglia
            nxt = [CryptoEngine.hash_sha256(b'\x01' + curr[i] + curr[i+1]) for i in range(0, len(curr), 2)]
            levels.append(nxt)
        self.tree_levels = levels

    def get_root(self) -> bytes:
        # Estrazione della Merkle Root
        return self.tree_levels[-1][0] if self.tree_levels else b'\x00'*32
    
    def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
        # Generazione del percorso logaritmico di inclusione (Merkle Proof) per la foglia specificata
        proof, curr_idx = [], index
        # Scorro tutti i livelli dell'albero escludendo la radice finale
        for level in self.tree_levels[:-1]:
            # Se l'indice corrente è pari, il gemello (sibling) necessario per l'hash si trova a destra
            if curr_idx % 2 == 0:
                proof.append((level[curr_idx + 1] if curr_idx + 1 < len(level) else level[curr_idx], 'right'))
            # Se l'indice è dispari, il gemello si trova a sinistra
            else:
                proof.append((level[curr_idx - 1], 'left'))
            # Spostamento dell'indice al livello superiore (divisione intera per due)
            curr_idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: List[Tuple[bytes, str]], expected_root: bytes) -> bool:
        # Algoritmo per la verifica induttiva della proof senza conoscere l'intero albero
        current = leaf_hash
        # Risalgo la catena dei sibling condizionando l'ordine di concatenazione alla direzione ('left' o 'right')
        for sib_hash, direction in proof:
            if direction == 'right':
                payload = b'\x01' + current + sib_hash
            else:
                payload = b'\x01' + sib_hash + current
            # Calcolo l'hash del livello superiore riutilizzando la separazione di dominio b'\x01'
            current = CryptoEngine.hash_sha256(payload)
        # L'inclusione è valida solo se il valore finale calcolato coincide esattamente con la radice attesa
        return current == expected_root