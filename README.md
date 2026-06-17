# Infrastruttura di Voto Condominiale Elettronico

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)

##  Descrizione

Una piattaforma avanzata per l'organizzazione di elezioni condominiali con **sicurezza crittografica**, **verificabilità universale** e **anonimato dell'elettore**. Il sistema implementa un protocollo di voto elettronico basato su:

- **Crittografia simmetrica** (AES-256 CBC) e **asimmetrica** (RSA-2048 OAEP)
- **Merkle Tree** per l'integrità dei dati
- **Token anonimi** firmati digitalmente
- **Bulletin Board pubblico** per la trasparenza
- **Auditing universale** accessibile a chiunque

##  Caratteristiche Principali

###  Sicurezza Crittografica
- **Cifratura ibrida**: AES-256 per dati, RSA per chiavi di sessione
- **Hashing**: SHA-256 per commitment e fingerprinting
- **Firma digitale**: RSA-PSS per autenticità dei token
- **Protezione dell'anonimato**: Token anonimo tau_i per disaccoppiare identità da voto

###  Verificabilità Universale
Il sistema implementa 8 livelli di ispezione (V.1-V.8):

1. **V.1 - Validità firme token**: Verifica che ogni token sul Bulletin Board sia stato autorizzato da RegistroElettorale
2. **V.2 - Assenza duplicati**: Controllo rigorosità contro il double-voting
3. **V.3 - Coerenza commitment**: Validazione matematica tra voti decifrati e Merkle Tree
4. **V.4 - Ricalcolo indipendente**: Conteggio dei risultati verificabile da osservatori esterni
5. **V.5 - Firma AE su risultato finale**: Validazione autenticità e non ripudio dei risultati firmati da AutoritaElettorale
6. **V.6 - Checkpoint intermedi**: Controllo di validità delle radici Merkle nei checkpoint periodici
7. **V.7 - Calcolabilità radice finale**: Ricostruzione integrale dell'albero di Merkle dalle foglie post-scrutinio
8. **V.8 - Catena batch**: Verifica autenticità e concatenazione dei blocchi parziali dei batch

###  Attori del Sistema
- **Elettore**: Autentica, riceve token anonimo, invia scheda cifrata
- **RegistroElettorale**: Autentica elettori, rilascia token firmati
- **AutoritaElettorale**: Riceve schede, gestisce scrutinio a batch
- **BulletinBoard**: Ledger pubblico immutabile di tutte le schede

###  Interfaccia Grafica
GUI intuitiva sviluppata in Tkinter con:
- Panel di configurazione parametri elezione
- Simulazione di voti condominiali
- Visualizzazione Bulletin Board in tempo reale
- Console di logging dettagliato
- Esecuzione audit universale

##  Struttura del Progetto

```
Progetto/
├── main_gui.py           # Applicazione GUI principale (Tkinter)
├── crypto_core.py        # Motore crittografico centralizzato
├── attori.py             # Implementazione attori del protocollo
└──audit.py              # Sistema di auditing universale
```

##  Installazione

### Prerequisiti
- Python 3.8+
- pip

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/Progetto_APS_Gruppo17.git
cd Progetto_APS_Gruppo17

# Installa dipendenze
pip install cryptography tkinter
```

##  Utilizzo

### Avviare l'Applicazione GUI

```bash
python Progetto/main_gui.py
```

La GUI offre un'interfaccia intuitiva per:
1. **Configurare parametri elezione** (numero condomini, numero candidati, durata votazione...)
2. **Simulare ciclo di voto** (autenticazione, voto, scrutinio)
3. **Monitorare Bulletin Board** in tempo reale
4. **Eseguire auditing universale** per verificare l'integrità

##  Autori

**Gruppo 17** - Progetto Algoritmi e Protocolli per la Sicurezza
* **Dello Russo Benedetta Lucia** 
* **Di Lieto Andrea** (Matricola: IE22700136)
