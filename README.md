# Dataplane Router - Tema 1

**Copyright 2024 Obreja Ana-Maria - Grupa 321CA**  
**Materia:** Protocoale de comunicatii

## Descriere proiect
Această temă implementează un program care simulează funcționalitățile 
unui router, capabil să proceseze pachete de tip IP, ARP request/reply 
și ICMP, utilizând un algoritm eficient de potrivire a celui mai lung 
prefix (Longest Prefix Match).

### Funcționalități implementate:
- **Protocolul IPV4**
- **Protocolul ARP**
- **Protocolul ICMP**
- **Longest Prefix Match** eficient

---

## Detalii de implementare

### 1. Protocolul IPV4
Router-ul procesează pachete de tip IP cu următorii pași:
- **Verificarea checksum-ului:** Dacă suma de control trimisă în pachet 
nu corespunde cu cea calculată, pachetul este ignorat (drop).
- **Verificarea și decrementarea TTL-ului:** TTL (time-to-live) este 
folosit pentru a evita loop-urile. La fiecare transmitere, TTL-ul este 
decrementat. Dacă ajunge la 0 sau 1, pachetul nu va mai fi trimis mai 
departe și se va trimite un pachet ICMP. 
- **Verificarea destinației:** Dacă pachetul este destinat router-ului, 
se trimite un pachet ICMP înapoi.

După aceste verificări, se decrementează TTL-ul, se recalculează suma 
de control și se caută cea mai bună intrare în tabela de routare. 
Dacă nu se găsește o intrare corespunzătoare, se trimite un pachet ICMP 
și se ignoră pachetul.

Dacă se găsește intrarea, se caută în tabela dinamică intrarea care 
conține adrese IP și MAC. Se compară adresa următorului hop cu cele 
din tabelă pentru a obține adresa MAC necesară modificării header-ului 
Ethernet și trimiterea pachetului. Dacă nu se găsește adresa IP, se 
trimite o cerere de tip broadcast tuturor nodurilor adiacente, iar 
pachetul este pus în așteptare până la primirea unui răspuns.

### 2. Protocolul ARP
- **ARP request:** Router-ul primește o cerere de tip broadcast și, 
dacă adresa sa IP este cea căutată, se construiește un pachet ARP_REPLY 
și este trimis către sursă.
- **ARP reply:** Un nod din rețea răspunde cererii de broadcast. Se 
caută în coada de pachete care așteaptă un astfel de răspuns și se 
trimite pachetul corespunzător.

### 3. Protocolul ICMP
Protocolul ICMP construiește un pachet care este trimis către sursa 
inițială pentru a semnala o problemă în dirijarea pachetului sau 
pentru a returna un "Echo reply".

### 4. LPM (Longest Prefix Match)
Pentru a eficientiza căutările, am folosit `qsort` pentru a sorta 
intrările din tabela de routare în funcție de prefix și masca de 
subrețea (în ordine crescătoare). Căutările din IPV4 se realizează 
prin `binary search`.

---

## Feedback
Tema a fost interesantă, iar lectura recomandată pentru realizarea 
temei s-a dovedit foarte utilă. În schimb, checker-ul a fost foarte 
dificil de folosit; uneori treceau testele, alteori nu, fără a schimba 
nimic în cod.
