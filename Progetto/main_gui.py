import os
import time
import random
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from typing import List

from crypto_core import CryptoEngine, MerkleTree
from attori import BulletinBoard, RegistroElettorale, AutoritaElettorale, Elettore
from audit import run_universal_audit

class CorporateVotingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Infrastruttura di Voto Condominiale Elettronico")
        
        # Dimensione del layout 
        self.geometry("1100x690")
        self.configure(bg="#f4f6f9")

        # Stato dell'applicazione e istanze del protocollo crittografico
        self.bb = None
        self.re = None
        self.ae = None
        self.condomini: List[Elettore] = []
        
        self.workspace = None
        self.console_frame = None
        self.log_box = None
        self.voti_inviati_count = 0
        self.tempi_inizio_interazione = {}
        
        # Rendering immediato del pannello di controllo dei parametri d'urna
        self.create_setup_frame()

    def log(self, message: str):
        # Canale di reindirizzamento dei log di back-end sulla console
        if self.log_box:
            self.log_box.insert(tk.END, f"{message}\n")
            self.log_box.see(tk.END)
        else:
            print(message)

    def create_setup_frame(self):
        # Pannello superiore per la configurazione dei vincoli numerici e temporali
        self.setup_panel = ttk.LabelFrame(self, text=" 1. CONFIGURAZIONE PARAMETRI ELEZIONE", padding=8)
        self.setup_panel.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        riga1 = ttk.Frame(self.setup_panel)
        riga1.pack(fill=tk.X, pady=2)
        riga2 = ttk.Frame(self.setup_panel)
        riga2.pack(fill=tk.X, pady=2)

        # Parametri dell'urna
        ttk.Label(riga1, text="Num. Elettori:").grid(row=0, column=0, padx=4, sticky=tk.W)
        self.ent_voters = ttk.Entry(riga1, width=6)
        self.ent_voters.insert(0, "13")
        self.ent_voters.grid(row=0, column=1, padx=4)

        ttk.Label(riga1, text="Num. Candidati:").grid(row=0, column=2, padx=4, sticky=tk.W)
        self.ent_candidates = ttk.Entry(riga1, width=6)
        self.ent_candidates.insert(0, "3")
        self.ent_candidates.grid(row=0, column=3, padx=4)

        ttk.Label(riga1, text="Batch Size (k):").grid(row=0, column=4, padx=4, sticky=tk.W)
        self.ent_batch = ttk.Entry(riga1, width=6)
        self.ent_batch.insert(0, "5")
        self.ent_batch.grid(row=0, column=5, padx=4)

        # Configurazione automatica delle date
        from datetime import datetime, timedelta
        data_oggi = datetime.now().strftime("%d/%m/%Y")
        data_domani = (datetime.now() + timedelta(days=1)).strftime("%d/%m/%Y")

        ttk.Label(riga2, text="Data Apertura (gg/mm/aaaa):").grid(row=0, column=0, padx=4, sticky=tk.W)
        self.ent_open = ttk.Entry(riga2, width=12)
        self.ent_open.insert(0, data_oggi)  
        self.ent_open.grid(row=0, column=1, padx=4)

        ttk.Label(riga2, text="Data Chiusura (gg/mm/aaaa):").grid(row=0, column=2, padx=4, sticky=tk.W)
        self.ent_close = ttk.Entry(riga2, width=12)
        self.ent_close.insert(0, data_domani)  
        self.ent_close.grid(row=0, column=3, padx=4)

        # Pulsanti di comando della pipeline principale
        self.btn_init = ttk.Button(riga2, text="⚙️ Inizializza Sistema", command=self.inizializza_sistema_elezione)
        self.btn_init.grid(row=0, column=4, padx=10)

        self.btn_fast_sim = ttk.Button(riga2, text="⚡ Simulazione Veloce", command=self.esegui_simulazione_veloce, state=tk.DISABLED)
        self.btn_fast_sim.grid(row=0, column=5, padx=3)

        self.btn_reset = ttk.Button(riga2, text="🔄 Reset", command=self.reset_sistema, state=tk.DISABLED)
        self.btn_reset.grid(row=0, column=6, padx=3)

    def inizializza_sistema_elezione(self):
        try:
            num_voters = int(self.ent_voters.get())
            num_candidates = int(self.ent_candidates.get())
            batch_k = int(self.ent_batch.get())

            if num_voters <= 0 or num_candidates <= 0 or batch_k <= 0:
                raise ValueError()
            
            if batch_k < 5:
                messagebox.showerror("Errore Parametri", "Il batch size k deve essere almeno 5 per garantire un'adeguata sicurezza crittografica.")
                return

            date_apertura = datetime.strptime(self.ent_open.get(), "%d/%m/%Y")
            date_chiusura = datetime.strptime(self.ent_close.get(), "%d/%m/%Y")
            
            # Controllo temporale bloccante: l'accesso si sblocca solo se l'apertura coincide con la data odierna
            oggi = datetime.now()
            if date_apertura.date() != oggi.date():
                messagebox.showerror("Validazione Data", f"La data di apertura delle urne non coincide con la data odierna ({oggi.strftime('%d/%m/%Y')}), quindi non puoi accedere al sistema.")
                return
            if date_chiusura < date_apertura:
                messagebox.showerror("Validazione Data", "La data di chiusura non può essere antecedente alla data di apertura.")
                return

        except ValueError:
            messagebox.showerror("Errore Input", "Controlla i parametri numerici e il formato data (gg/mm/aaaa).")
            return

        # Generazione e interconnessione delle entità crittografiche
        self.bb = BulletinBoard()
        self.re = RegistroElettorale()
        self.ae = AutoritaElettorale(k_anonimato=batch_k, pk_RE=self.re.pk_RE, bb=self.bb)

        # Pubblicazione delle chiavi pubbliche e dei metadati di base sul BB
        self.bb.pk_AE = self.ae.pk_AE
        self.bb.pk_RE = self.re.pk_RE
        self.bb.L = [f"Candidato {chr(65+i)}" for i in range(num_candidates)]
        self.bb.date = f"Apertura: {self.ent_open.get()} | Chiusura: {self.ent_close.get()}"

        # Simulazione fase di Enrollment fuori banda: generazione identità e chiavi simmetriche segrete K_i
        self.condomini = []
        for i in range(num_voters):
            id_name = f"Elettore_{chr(65 + (i % 26))}{i // 26 if i >= 26 else ''}"
            k_simmetrica = os.urandom(32)
            self.re.register_condomino(id_name, k_simmetrica)
            self.condomini.append(Elettore(id_name, k_simmetrica))

        self.voti_inviati_count = 0
    
        # Istanziazione dei pannelli visivi 
        self.build_three_sections_layout()
        
        # Tracciamento lineare e sequenziale delle operazioni di setup del protocollo in console
        self.log("[FASE DI SETUP] Generazione chiavi asimmetriche RSA-2048 per l'Autorità Elettorale (AE)...")
        self.log(f"[FASE DI SETUP] AE pubblica tutti i parametri sul Bulletin Board (BB) -> Lista Candidati: {self.bb.L} | Date: {self.ent_open.get()} - {self.ent_close.get()} | Batch k: {batch_k}")
        self.log("[FASE DI SETUP] Generazione chiavi asimmetriche RSA-2048 per il Registro Elettorale (RE)...")
        self.log("[FASE DI SETUP] RE pubblica la chiave pubblica pk_RE sul Bulletin Board (BB) per consentire le future verifiche pubbliche dei token.")
        self.log(f"[FASE DI SETUP] Enrollment Sicuro (Fuori Banda): Registrate le identità ed emesse {num_voters} chiavi simmetriche K_i segrete nei dispositivi dei condomini.")
        self.log("[✓ SETUP COMPLETATO] Sistema configurato e pronto per ricevere le richieste di voto.")
        
        self.btn_init.config(state=tk.DISABLED)
        self.btn_fast_sim.config(state=tk.NORMAL)
        self.btn_reset.config(state=tk.NORMAL)
        self.refresh_re_display()
        self.refresh_bb_display()

    def build_three_sections_layout(self):
        # Ripartizione geometrica dello schermo: pannello flussi guidati, tabellone pubblico e console log
        self.workspace = ttk.Frame(self, padding=2)
        self.workspace.pack(fill=tk.BOTH, expand=True, padx=10, pady=2)

        split_paned = tk.PanedWindow(self.workspace, orient=tk.HORIZONTAL, bd=0, bg="#f4f6f9")
        split_paned.pack(fill=tk.BOTH, expand=True)

        # SEZIONE 1: TABELLONE REGISTRO RE (SINISTRA)
        self.re_frame = ttk.LabelFrame(split_paned, text=" SEZIONE 1: Registro Elettorale (RE)", padding=5)
        
        flow_panel = ttk.LabelFrame(self.re_frame, text="Flusso Interattivo", padding=5)
        flow_panel.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))

        ttk.Label(flow_panel, text="Seleziona Elettore:").pack(anchor=tk.W)
        self.combo_elettori = ttk.Combobox(flow_panel, state="readonly")
        self.combo_elettori.pack(fill=tk.X, pady=2)
        self.combo_elettori['values'] = [c.id_i for c in self.condomini]
        self.combo_elettori.current(0)
        self.combo_elettori.bind("<<ComboboxSelected>>", self.on_elettore_cambiato)

        self.btn_token = ttk.Button(flow_panel, text="1. Richiedi Token (Challenge/Response)", command=self.esegui_handshake_manuale)
        self.btn_token.pack(fill=tk.X, pady=3)

        self.vote_subpanel = ttk.LabelFrame(flow_panel, text=" Cabina Elettorale ", padding=5)
        self.vote_subpanel.pack(fill=tk.X, pady=3)
        
        self.combo_voto = ttk.Combobox(self.vote_subpanel, state="readonly")
        self.combo_voto.pack(fill=tk.X, pady=2)
        self.combo_voto['values'] = self.bb.L
        self.combo_voto.current(0)

        self.btn_cast_vote = ttk.Button(self.vote_subpanel, text="2. Cifra ed Invia Voto", command=self.esegui_voto_manuale, state=tk.DISABLED)
        self.btn_cast_vote.pack(fill=tk.X, pady=3)

        self.re_tree = ttk.Treeview(self.re_frame, columns=("id", "token_status"), show="headings", height=8)
        self.re_tree.heading("id", text="ID Elettore")
        self.re_tree.heading("token_status", text="Stato Token RE")
        self.re_tree.column("id", width=120)
        self.re_tree.column("token_status", width=110, anchor=tk.CENTER)
        self.re_tree.pack(fill=tk.BOTH, expand=True)

        # SEZIONE 2: BULLETIN BOARD (DESTRA) 
        self.bb_frame = ttk.LabelFrame(split_paned, text=" SEZIONE 2: Bulletin Board (BB) ", padding=5)
        
        audit_bar = ttk.Frame(self.bb_frame)
        audit_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))

        self.btn_scrutinio = ttk.Button(audit_bar, text="🗳️ Scrutina Batch", command=self.esegui_scrutinio_gui, state=tk.DISABLED)
        self.btn_scrutinio.pack(side=tk.LEFT, padx=2)

        self.btn_scrutinio_tutti = ttk.Button(audit_bar, text="🗳️ Scrutina tutti i batch", command=self.esegui_scrutinio_totale_gui, state=tk.DISABLED)
        self.btn_scrutinio_tutti.pack(side=tk.LEFT, padx=2)

        btn_audit_uni = ttk.Button(audit_bar, text="🌐 Verifica Universale", command=self.verifica_universale_gui)
        btn_audit_uni.pack(side=tk.LEFT, padx=2)

        btn_audit_ind = ttk.Button(audit_bar, text="🔍 Verifica Individuale", command=self.verifica_individuale_gui)
        btn_audit_ind.pack(side=tk.LEFT, padx=2)
        
        # "Chi sei?" serve per sbloccare la verifica individuale: l'elettore seleziona la propria identità 
        # e il sistema confronta quanto nella memoria locale con quello presente sul BB
        ttk.Label(audit_bar, text=" Chi sei?:").pack(side=tk.LEFT, padx=2)
        self.combo_verifica_ind = ttk.Combobox(audit_bar, state="readonly", width=14)
        self.combo_verifica_ind.pack(side=tk.LEFT, padx=2)
        self.combo_verifica_ind['values'] = [c.id_i for c in self.condomini]
        self.combo_verifica_ind.current(0)

        columns = ("index", "tau", "commitment", "omega", "clear_vote")
        self.bb_tree = ttk.Treeview(self.bb_frame, columns=columns, show="headings", height=8)
        self.bb_tree.heading("index", text="Riga")
        self.bb_tree.heading("tau", text="Token (tau)")
        self.bb_tree.heading("commitment", text="Commitment (h_i)")
        self.bb_tree.heading("omega", text="Verifica (Omega)")
        self.bb_tree.heading("clear_vote", text="Voto Chiaro")
        
        self.bb_tree.column("index", width=40, anchor=tk.CENTER)
        self.bb_tree.column("tau", width=105)
        self.bb_tree.column("commitment", width=145)
        self.bb_tree.column("omega", width=145)
        self.bb_tree.column("clear_vote", width=135)
        self.bb_tree.pack(fill=tk.BOTH, expand=True)

        self.result_panel = ttk.LabelFrame(self.bb_frame, text=" 📊 ESITO DELLO SCRUTINIO ", padding=5)
        self.result_panel.pack(side=tk.BOTTOM, fill=tk.X, pady=4)
        self.lbl_final_res = ttk.Label(self.result_panel, text="Urne aperte. In attesa del completamento delle operazioni...", font=("Helvetica", 10, "italic"), foreground="#7f8c8d")
        self.lbl_final_res.pack(anchor=tk.W)

        split_paned.add(self.re_frame, width=290)
        split_paned.add(self.bb_frame, width=810)

        # SEZIONE 3: CONSOLE CRITTOGRAFICA (IN FONDO) 
        self.console_frame = ttk.LabelFrame(self, text=" SEZIONE 3: Console log eventi crittografici di back-end ", padding=5)
        self.console_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        
        self.log_box = scrolledtext.ScrolledText(self.console_frame, height=8, bg="#1a1a1a", fg="#33ff33", font=("Consolas", 9))
        self.log_box.pack(fill=tk.X, expand=True)

    def on_elettore_cambiato(self, event):
        # Automa a stati finiti della GUI: blocca o sblocca i pulsanti per forzare l'ordine logico del protocollo
        idx = self.combo_elettori.current()
        elettore = self.condomini[idx]
        if self.re.issued_tokens[elettore.id_i]:
            if elettore.tau_i in self.ae.used_tokens:
                self.btn_cast_vote.config(state=tk.DISABLED) # Scheda già spesa, disabilita invio
            else:
                self.btn_cast_vote.config(state=tk.NORMAL) # Token ritirato ma non ancora speso
        else:
            self.btn_cast_vote.config(state=tk.DISABLED) # Manca il token, obbliga a fare prima l'handshake

    def esegui_handshake_manuale(self):
        # Esecuzione manuale passo-passo dell'handshake simmetrico basato su sfida (Challenge/Response)
        idx = self.combo_elettori.current()
        elettore = self.condomini[idx]
        id_i = elettore.id_i

        if self.re.issued_tokens[id_i]:
            messagebox.showwarning("Allerta", f"Token già rilasciato per {id_i}! RE rifiuta doppie emissioni.")
            return

        self.log(f"\n--- FASE DI HANDSHAKE CHALLENGE/RESPONSE PER {id_i} ---")
        self.tempi_inizio_interazione[id_i] = time.perf_counter()  # Timestamp di inizio interazione per monitoraggio temporale

        elettore.esegui_handshake(self.re)
        self.log(f"[✓] Risposta simmetrica AES-CBC convalidata dal database di RE.")
        self.log(f"[RE -> Client] Rilasciato pacchetto token firmato in RSA-PSS.")
        
        self.refresh_re_display()
        self.btn_cast_vote.config(state=tk.NORMAL)

    def esegui_voto_manuale(self):
        # Fase di cifratura e iniezione della scheda anonima sul BB pubblico
        idx = self.combo_elettori.current()
        elettore = self.condomini[idx]
        cand_idx = self.combo_voto.current()
        
        self.log(f"\n--- FASE DI PREPARAZIONE E RICEZIONE SCHEDA ---")
        elettore.voto_e_prepara(cand_idx, self.ae)
        self.log(f"[Hybrid Encryption] Generato payload cifrato (AES-CBC) + chiave di sessione (RSA-OAEP).")
        self.log(f"[✓] Scheda validata dall'AE e registrata sul Bulletin Board pubblici.")
        
        t_inizio = self.tempi_inizio_interazione.get(elettore.id_i)
        if t_inizio:
            durata = (time.perf_counter() - t_inizio) * 1000
            self.log(f"   ↳ [METRICA] Tempo totale di interazione per {elettore.id_i}: {durata:.2f} ms (Handshake + Cifratura Ibrida)")

        # Stampa in chiaro del tracciato logaritmico della Merkle Proof pre-scrutinio
        if elettore.pi_i:
            proof_str = ", ".join([f"({sib.hex()[:8]}..., {direc})" for sib, direc in elettore.pi_i])
            self.log(f" ↳ [MERKLE PROOF GENERATA] {elettore.id_i} -> Percorso logaritmico: [{proof_str}]")
        else:
            self.log(f" ↳ [MERKLE PROOF GENERATA] {elettore.id_i} -> Root provvisoria (Prima foglia dell'albero).")

        self.btn_cast_vote.config(state=tk.DISABLED)
        self.refresh_re_display()
        self.refresh_bb_display()
        self.check_if_scrutinio_ready()

    def check_if_scrutinio_ready(self):
        # L'attivazione dello scrutinio si sblocca unicamente quando l'urna raccoglie il 100% delle schede attese
        if len(self.bb.records) == len(self.condomini):
            self.btn_scrutinio.config(state=tk.NORMAL)
            self.btn_scrutinio_tutti.config(state=tk.NORMAL)
            self.log(f"\n🗳️ [URNA CHIUSA] Tutti i condomini registrati hanno votato. Pulsante di scrutinio abilitato.")

    def esegui_scrutinio_gui(self):
        # De-anonimizzazione a batch e verifica in console del vincolo SHA-256(V_j) == h_j
        self.log(f"\n--- FASE DI SCRUTINIO DEL BATCH {self.ae.current_batch_index} ---")
        start, end, all_done, shuffled = self.ae.scrutina_singolo_batch(logger=self.log)
        
        self.log(f"[BATCH] Si processano i record da riga {start} a {end} (Schede elaborate: {end-start}).")
        self.log(f"[SHUFFLING] Permutazione casuale applicata al blocco: {shuffled}")
        
        self.refresh_bb_display()
        
        # Se tutti i lotti sono terminati, pubblica il risultato consolidato e decreta il vincitore dell'assemblea
        if all_done:
            self.btn_scrutinio.config(state=tk.DISABLED)
            res = self.bb.final_result["R_final"]
            vincitore = max(res, key=res.get)
            
            tally_str = " | ".join([f"{self.bb.L[k]}: {v} preferenze" for k, v in res.items()])
            self.lbl_final_res.config(
                text=f"SCRUTINIO COMPLETATO!\nRisultati finali: {tally_str}\n\n Eletto: {self.bb.L[vincitore]}",
                font=("Helvetica", 10, "bold"), foreground="#27ae60"
            )
            self.log(f"\n[RISULTATO] Elezione conclusa. Esito pubblicato sul BB: {res}")
            messagebox.showinfo("Esito Assemblea", f"Scrutinio ultimato!\nNuovo Amministratore: {self.bb.L[vincitore]}")

    def esegui_scrutinio_totale_gui(self):
        self.log(f"\n--- AVVIO SCRUTINIO AUTOMATICO DI TUTTI I BATCH ---")
        t_inizio = time.perf_counter()
        all_done = False
        
        while not all_done:
            start, end, all_done, shuffled = self.ae.scrutina_singolo_batch(logger=None)
            self.log(f" ↳ [BATCH COMPLETATO] Elaborato batch righe {start} a {end} (k={self.ae.k}).")
        
        durata = (time.perf_counter() - t_inizio) * 1000
        self.log(f"[✓] SCRUTINIO ULTIMATO in {durata:.2f} ms per {len(self.bb.records)} schede.")
        
        self.refresh_bb_display()
        self.btn_scrutinio.config(state=tk.DISABLED)
        self.btn_scrutinio_tutti.config(state=tk.DISABLED)
        
        res = self.bb.final_result["R_final"]
        vincitore = max(res, key=res.get)
        tally_str = " | ".join([f"{self.bb.L[k]}: {v} preferenze" for k, v in res.items()])
        self.lbl_final_res.config(
            text=f"SCRUTINIO COMPLETATO!\nRisultati finali: {tally_str}\n\n Eletto: {self.bb.L[vincitore]}",
            font=("Helvetica", 10, "bold"), foreground="#27ae60"
        )
        messagebox.showinfo("Esito votazione", f"Scrutinio di tutti i lotti completato con successo!\nNuovo Amministratore: {self.bb.L[vincitore]}")

    def refresh_re_display(self):
        # Sincronizzazione visiva del registro d'identità gestito dal RE
        for item in self.re_tree.get_children():
            self.re_tree.delete(item)
        for c in self.condomini:
            status = "Nessun Token"
            if self.re.issued_tokens[c.id_i]:
                status = "Token Rilasciato"
            if c.tau_i in self.ae.used_tokens:
                status = "Scheda Spesa X"
            self.re_tree.insert("", tk.END, values=(c.id_i, status))

    def refresh_bb_display(self):
        # Sincronizzazione del tabellone del BB esposto alla verifica pubblica
        for item in self.bb_tree.get_children():
            self.bb_tree.delete(item)
        for idx, r in enumerate(self.bb.records):
            v_disp = "🔒 Cifrato"
            if r["voto_chiaro"] is not None:
                v_disp = "ANNULLATA" if r["voto_chiaro"] == "ANNULLATA" else f"{self.bb.L[r['voto_chiaro']]}"
            
            omega_disp = r["Omega_i"].hex()[:12] + "..." if r["Omega_i"] != b'\x00'*32 else "0x0000... (Pad)"
            self.bb_tree.insert("", tk.END, values=(
                idx, r["tau_i"].hex()[:8] + "...", r["h_i"].hex()[:12] + "...", omega_disp, v_disp
            ))

    def esegui_simulazione_veloce(self):
        # Stress-test di robustezza anonima: simula la votazione disordinata rimescolando l'array degli utenti
        self.log("\n --- RUNNING SIMULAZIONE VELOCE (con pipeline disordinata) ---")
        
        elettori_shuffled = self.condomini[:]
        random.shuffle(elettori_shuffled) # Mescolamento per rompere la sequenzialità alfabetica sul BB
        
        for c in elettori_shuffled:
            t_inizio = time.perf_counter() # Inizio tracking per l'elettore c
            if not self.re.issued_tokens[c.id_i]:
                c.esegui_handshake(self.re)
            if c.tau_i not in self.ae.used_tokens:
                voto_casuale = random.randint(0, len(self.bb.L) - 1)
                c.voto_e_prepara(voto_casuale, self.ae)
            
            durata = (time.perf_counter() - t_inizio) * 1000 # Fine tracking
            self.log(f"[METRICA] {c.id_i} ha completato il flusso in: {durata:.2f} ms")
        
        self.refresh_re_display()
        self.refresh_bb_display()
        self.check_if_scrutinio_ready()
        self.btn_fast_sim.config(state=tk.DISABLED)

    def reset_sistema(self):
        # Permette di reinizializzare il sistema e la memoria grafica
        if self.log_box:
            self.log_box.delete("1.0", tk.END)
        
        if self.workspace:
            self.workspace.destroy()
        if self.console_frame:
            self.console_frame.destroy()
        if self.setup_panel:
            self.setup_panel.destroy()
            
        self.bb = None
        self.re = None
        self.ae = None
        self.condomini = []
        self.log_box = None
        self.workspace = None
        self.console_frame = None
        
        self.create_setup_frame()
        self.btn_init.config(state=tk.NORMAL)

    def item_index(self, tree):
        sel = tree.selection()
        return int(tree.item(sel, "values")[0]) if sel else None

    def i_elettore(self, index):
        return self.condomini[index]

    def verifica_individuale_gui(self):
        # ALGORITMO DI VERIFICABILITÀ INDIVIDUALE: mappato su 5 passi 
        if not self.bb or not self.bb.records:
            messagebox.showwarning("Verifica Individuale", "Il tabellone del Bulletin Board è vuoto."); return

        elettore_nome = self.combo_verifica_ind.get()
        if not elettore_nome:
            messagebox.showwarning("Verifica Individuale", "Seleziona prima l'elettore dal menu 'Chi sei?'."); return

        t_inizio = time.perf_counter() # Inizio tracking temporale per la verifica individuale

        elettore = None
        for c in self.condomini:
            if c.id_i == elettore_nome:
                elettore = c
                break

        if not elettore or not elettore.tau_i:
            messagebox.showwarning("Errore Client", f"Non hai ancora espresso un voto.\n ID_elettore: {elettore_nome}."); return

        # TUTELA DELLO PSEUDO-ANONIMATO: scansione lineare del BB cercando il MATCH sul Token tau_i privato dell'elettore.
        # Questo permette al client di trovare il proprio record a prescindere dall'ordine di sottomissione
        bb_idx = None
        for idx, r in enumerate(self.bb.records):
            if r["tau_i"] == elettore.tau_i:
                bb_idx = idx
                break

        if bb_idx is None:
            messagebox.showerror("Errore BB", "Token non trovato sul Bulletin Board."); return

        record = self.bb.records[bb_idx]
        if record["voto_chiaro"] is None:
            messagebox.showwarning("Urna Aperta", "Impossibile verificare: il tuo batch non è ancora stato scrutinato."); return

        self.log(f"\n--- VERIFICA INDIVIDUALE (Elettore: {elettore.id_i} -> Riga BB rintracciata: {bb_idx}) ---")

        # PASSO 1: Recupero locale della stringa di voto originaria in chiaro V_i
        v_i = bytes([elettore.voto]) + elettore.tau_i + elettore.r_i
        self.log(f" [Passo 1] Recupero dal proprio archivio locale la scheda in chiaro originaria: V_i = c_i || tau_i || r_i")
        self.log(f"   ↳ c_i (voto): {elettore.voto} ({self.bb.L[elettore.voto]})")
        self.log(f"   ↳ tau_i (token): {elettore.tau_i.hex()[:16]}...")
        self.log(f"   ↳ r_i (nonce conservato - PRECONDIZIONE): {elettore.r_i.hex()[:16]}...")

        # PASSO 2: Computazione indipendente dell'hash di riscontro post-scrutinio
        omega_star = CryptoEngine.hash_sha256(v_i)
        self.log(f" [Passo 2] Calcolo dell'hash di riscontro post-scrutinio: Omega_i* = SHA-256(V_i)")
        self.log(f"   ↳ Omega_i* risultante: {omega_star.hex()[:32]}...")

        # PASSO 3: Validazione incrociata tra i dati esposti sul BB e le costanti computate in locale dal client
        self.log(f" [Passo 3] Scaricamento riga dal BB e controllo coerenza del lavoro di AE...")
        self.log(f"   ↳ Verifica uguaglianza voto: BB[{bb_idx}].voto_chiaro ({record['voto_chiaro']}) == c_i ({elettore.voto})")
        self.log(f"   ↳ Verifica uguaglianza nodo: BB[{bb_idx}].Omega_i ({record['Omega_i'].hex()[:12]}...) == Omega_i* ({omega_star.hex()[:12]}...)")
        
        match_voto = record["voto_chiaro"] == elettore.voto
        match_hash = record["Omega_i"] == omega_star
        
        if not match_voto or not match_hash:
            self.log("   [-] ESITO PASSO 3: FALLITO! Rilevata alterazione fraudolenta dei dati sul BB.")
            messagebox.showerror("Allerta Frode", "FALLITO: Il voto o il commitment sul BB sono stati manipolati!")
            return
        self.log("   ↳ [✓] Esito riscontro: Il voto e il commitment coincidono perfettamente con i dati esposti.")

        # PASSO 4: Rigenerazione locale della foglia post-scrutinio (con separatore di dominio b'\x00')
        h_i_post = CryptoEngine.hash_sha256(b'\x00' + elettore.tau_i + record["h_i"] + omega_star)
        self.log(f" [Passo 4] Rigenerazione della propria foglia post-scrutinio locale: H_i^post = SHA-256(0x00 || tau_i || h_i || Omega_i*)")
        self.log(f"   ↳ H_i^post generata localmente: {h_i_post.hex()[:32]}...")

        # PASSO 5: Ricostruzione del cammino d'albero tramite la Merkle Proof e risalita fino a R_final
        tree_v = MerkleTree()
        tree_v.build_tree([CryptoEngine.hash_sha256(b'\x00' + r["tau_i"] + r["h_i"] + r["Omega_i"]) for r in self.bb.records])
        proof = tree_v.get_proof(bb_idx)
        root_finale = tree_v.get_root()

        self.log(f" [Passo 5] Richiesta al BB della Merkle Proof pi_i ed esecuzione dell'algoritmo di risalita fino alla Radice...")
        self.log(f"   ↳ Sibling del percorso recuperati: {[p[0].hex()[:10]+'...' for p in proof]}")
        self.log(f"   ↳ R_final attesa firmata dall'AE:  {root_finale.hex()[:32]}...")

        if MerkleTree.verify_proof(h_i_post, proof, root_finale):
            self.log("   ↳ [✓] RISALITA COMPLETATA: La radice calcolata coincide con R_final. Nessuna alterazione retroattiva sul tabellone.")
            messagebox.showinfo("Audit Personale", "✓ CERTEZZA ASSOLUTA: Il tuo voto è stato fedelmente conteggiato e non ha subito manipolazioni.")
            durata = (time.perf_counter() - t_inizio) * 1000
            self.log(f"   ↳ [METRICA] Tempo computazionale Verifica Individuale: {durata:.4f} ms")
        else:
            self.log("   ↳ [-] RISALITA FALLITA: La proof ha generato una radice non coerente!")
            messagebox.showerror("Errore Albero", "FAIL: La Merkle Proof non è valida rispetto alla radice finale firmata.")

    def verifica_universale_gui(self):
        # Attivazione della Verifica Universale delegato al modulo dedicato
        if not self.bb or not self.bb.records:
            messagebox.showwarning("Verifica Universale", "Nessun record presente sul Bulletin Board. Avvia prima le operazioni di voto.")
            return

        self.log("\n--- AVVIO VERIFICABILITÀ UNIVERSALE ---")
        
        t_inizio = time.perf_counter() # Inizio tracking temporale per l'audit universale
        
        res_logs = run_universal_audit(self.bb)
        for line in res_logs:
            self.log(line)

        durata = (time.perf_counter() - t_inizio) * 1000
        self.log(f"   ↳ [METRICA] Tempo computazionale Verifica Universale: {durata:.2f} ms")
        
        if any("FALLITO" in l for l in res_logs):
            messagebox.showerror("Verifica Universale", "FALLITO: Rilevate incongruenze crittografiche nel registro d'urna.")
        else:
            messagebox.showinfo("Verifica Universale", "✓ COMPLETATO: Integrità globale e catena dei checkpoint verificate con successo.")

if __name__ == "__main__":
    app = CorporateVotingApp()
    app.mainloop()