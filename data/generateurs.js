/* Exercices générés au hasard. ch = index du chapitre dans COURS.chapitres :
   0 bases · 1 risques · 2 RGPD · 3 attaques · 4 crypto · 5 accès · 6 réseau ·
   7 supervision · 8 disponibilité · 9 identité · 10 références */
(() => {
const { R, pick, shuf, T, fr, box } = OUT;
const G = COURS.generes;
const extIp = () => `${pick([185, 45, 91, 103, 194])}.${R(10, 250)}.${R(1, 254)}.${R(1, 254)}`;
const pad = n => String(n).padStart(2, "0");

/* ---------- 1. Logs SSH : force brute */
G.push({ titre: "Analyser un journal SSH", niv: 2, ch: 7, gen() {
  const att = extIp(), srv = pick(["srv-web01", "srv-files", "gw-vpn", "srv-mail"]);
  const comptes = shuf(["root", "admin", "test", "oracle", "ubuntu", "support"]).slice(0, R(1, 3));
  const h = R(0, 5), m0 = R(0, 40), n = R(6, 9), succes = Math.random() < 0.5;
  const victime = pick(comptes);
  let lignes = [], s = R(0, 20);
  for (let i = 0; i < n; i++) { s += R(1, 3); const u = pick(comptes); lignes.push(`Nov 18 ${pad(h)}:${pad(m0 + Math.floor(s / 60))}:${pad(s % 60)} ${srv} sshd[${4100 + i}]: Failed password for ${u === "test" || u === "oracle" ? "invalid user " : ""}${u} from ${att} port ${R(40000, 60000)} ssh2`); }
  if (succes) { s += 2; lignes.push(`Nov 18 ${pad(h)}:${pad(m0 + Math.floor(s / 60))}:${pad(s % 60)} ${srv} sshd[${4100 + n}]: Accepted password for ${victime} from ${att} port ${R(40000, 60000)} ssh2`); }
  lignes.splice(R(1, 3), 0, `Nov 18 ${pad(h)}:${pad(m0)}:01 ${srv} sshd[3990]: Accepted publickey for jdupont from 192.168.10.${R(20, 90)} port 51022 ssh2`);
  return { q: `<p>Extrait du fichier <code>/var/log/auth.log</code> du serveur <b>${srv}</b> :</p><pre class="log">${lignes.join("\n")}</pre><ol><li>Quelle attaque est en cours ? Justifiez avec le journal.</li><li>Relevez l'adresse source, les comptes visés et la plage horaire.</li><li>L'attaque a-t-elle réussi ? Quelles conséquences ?</li><li>Proposez des mesures immédiates et durables.</li></ol>`,
    c: `<ol><li><b>Attaque par force brute / dictionnaire</b> sur SSH : ${n} échecs (« Failed password ») en quelques secondes depuis la même IP, sur des comptes génériques${comptes.some(c => c === "test" || c === "oracle") ? " (dont des comptes inexistants : « invalid user »)" : ""}. La connexion de jdupont depuis le LAN par clé publique est normale.</li><li>Source : <b>${att}</b> (IP externe) ; comptes : <b>${comptes.join(", ")}</b> ; vers ${pad(h)} h ${pad(m0)}, en pleine nuit.</li><li>${succes ? `<b>Oui</b> : la dernière ligne « Accepted password for ${victime} » montre que l'attaquant a trouvé le mot de passe. Le serveur est compromis : atteinte possible à la <b>confidentialité</b> et à l'<b>intégrité</b>, rebond vers le reste du réseau.` : "<b>Non</b> d'après cet extrait : aucune ligne « Accepted » depuis cette IP. Mais il faut surveiller la suite."}</li><li><b>Immédiat :</b> bloquer l'IP sur le pare-feu${succes ? `, isoler le serveur, désactiver le compte ${victime} et changer son mot de passe, analyser ce qui a été fait (historique, fichiers modifiés, nouveaux comptes), conserver les journaux comme preuves` : ""}. <b>Durable :</b> interdire la connexion root (<code>PermitRootLogin no</code>), authentification par clé uniquement (<code>PasswordAuthentication no</code>), fail2ban, SSH accessible seulement via VPN ou depuis le réseau d'administration, changement du port en complément, centralisation des journaux dans un SIEM avec alerte.</li></ol>` };
}});

/* ---------- 2. Logs Windows */
G.push({ titre: "Analyser des événements Windows", niv: 2, ch: 7, gen() {
  const u = pick(["m.bernard", "s.leroy", "compta01", "a.petit"]), poste = `PC-${pick(["COMPTA", "RH", "ACCUEIL", "DIR"])}-${R(1, 9)}`;
  const src = `10.${R(0, 5)}.${R(10, 60)}.${R(2, 250)}`, n = R(5, 8), h = pick([2, 3, 23, 13]);
  const verrou = Math.random() < 0.5;
  const rows = [];
  for (let i = 0; i < n; i++) rows.push([`${pad(h)}:${pad(10 + Math.floor(i / 2))}:${pad(R(0, 59))}`, "4625", u, src, "Échec d'ouverture de session (mot de passe incorrect)"]);
  rows.push([`${pad(h)}:${pad(15)}:${pad(R(0, 59))}`, verrou ? "4740" : "4624", u, verrou ? "–" : src, verrou ? "Le compte a été verrouillé" : "Ouverture de session réussie (type 3, réseau)"]);
  if (!verrou && Math.random() < 0.6) rows.push([`${pad(h)}:${pad(17)}:${pad(R(0, 59))}`, "4720", u, "–", "Création du compte « svc_backup2 »"]);
  const cree = rows.some(r => r[1] === "4720");
  return { q: `<p>Extrait de l'observateur d'événements du contrôleur de domaine (compte <b>${u}</b>, qui travaille sur ${poste}) :</p>${T(["Heure", "ID", "Compte", "Adresse source", "Description"], rows)}<ol><li>Interprétez la séquence d'événements.</li><li>Quels éléments sont suspects ?</li><li>Quelles actions menez-vous ?</li></ol>`,
    c: `<ol><li>${n} événements <b>4625</b> (échecs) en quelques minutes sur le compte ${u}, puis ${verrou ? "<b>4740</b> : le compte est <b>verrouillé</b> par la stratégie de verrouillage, l'attaque est stoppée." : `<b>4624</b> : une <b>ouverture de session réussie</b> depuis la même adresse : le mot de passe a probablement été trouvé.${cree ? " Puis <b>4720</b> : création d'un compte « svc_backup2 » : l'attaquant crée une <b>porte dérobée</b> (persistance) avec un nom qui imite un compte de service." : ""}`}</li><li>Heure (${h} h${h === 13 ? ", pause déjeuner, l'utilisateur est absent" : ", hors des heures de travail"}) ; adresse source ${src} qui n'est pas forcément celle du poste habituel ; rafale d'échecs (attaque automatisée, poste interne probablement compromis).</li><li>${verrou ? "Identifier la machine " + src + " et l'analyser (logiciel malveillant ?), prévenir l'utilisateur, déverrouiller le compte après changement du mot de passe, surveiller les autres comptes visés depuis cette adresse." : `<b>Contenir</b> : isoler la machine ${src}, désactiver ${u} et réinitialiser son mot de passe${cree ? ", désactiver/supprimer « svc_backup2 » après avoir conservé les preuves" : ""}. <b>Investiguer</b> : ce qui a été fait avec le compte, autres comptes touchés. <b>Durcir</b> : verrouillage après 5 échecs par GPO, MFA, alertes SIEM sur 4625 en rafale, 4720 et 4732.`}</li></ol>` };
}});

/* ---------- 3. Pare-feu : quelle règle s'applique ? */
G.push({ titre: "Évaluer des flux face au pare-feu", niv: 2, ch: 6, gen() {
  const web = `172.16.0.${R(10, 20)}`, mail = `172.16.0.${R(21, 30)}`, lan = `192.168.${R(1, 20)}.0/24`, ad = `192.168.${R(21, 30)}.10`;
  const lanP = lan.replace(".0/24", "");
  const regles = [["1", "any", web, "TCP 443", "Autoriser"], ["2", "any", mail, "TCP 25", "Autoriser"], ["3", lan, "any", "TCP 80, 443", "Autoriser"], ["4", lan, ad, "TCP/UDP 53, 88, 389", "Autoriser"], ["5", "any", web, "TCP 22", "Refuser"], ["6", "192.168.99.0/24 (admin)", "172.16.0.0/24", "TCP 22", "Autoriser"], ["7", "any", "any", "any", "Refuser"]];
  const flux = shuf([
    [`Internet (${extIp()})`, web, "TCP 443", "règle 1 : autorisé"],
    [`Internet (${extIp()})`, web, "TCP 22", "règle 5 : refusé"],
    [`${lanP}.${R(20, 200)}`, "un site web externe", "TCP 443", "règle 3 : autorisé"],
    [`${lanP}.${R(20, 200)}`, ad, "TCP 389", "règle 4 : autorisé"],
    [`192.168.99.${R(2, 20)}`, web, "TCP 22", "règle 5 : <b>refusé</b> (la règle 5 « any » est lue avant la règle 6)"],
    [`Internet (${extIp()})`, ad, "TCP 3389", "règle 7 : refusé (règle par défaut)"],
    [web, `${lanP}.${R(20, 200)}`, "TCP 445", "règle 7 : refusé (la DMZ ne doit pas joindre le LAN)"],
    [`${lanP}.${R(20, 200)}`, mail, "TCP 25", "règle 7 : refusé (aucune règle LAN → DMZ sur 25)"],
  ]).slice(0, 5);
  const piege = flux.some(f => f[0].startsWith("192.168.99"));
  return { q: `<p>Table de filtrage (DMZ 172.16.0.0/24, LAN ${lan}, réseau d'administration 192.168.99.0/24) :</p>${T(["N°", "Source", "Destination", "Service", "Action"], regles)}<p>Pour chaque flux, indiquez la règle appliquée et le résultat :</p>${T(["Source", "Destination", "Service"], flux.map(f => f.slice(0, 3)))}${piege ? "<p>Que constatez-vous pour les administrateurs ? Corrigez.</p>" : "<p>Pourquoi la règle 7 est-elle indispensable ?</p>"}`,
    c: `${T(["Flux", "Résultat"], flux.map(f => [`${f[0]} → ${f[1]} (${f[2]})`, f[3]]))}<p>Les règles sont lues <b>de haut en bas</b>, la <b>première qui correspond</b> s'applique.</p>${piege ? "<p><b>Problème d'ordre :</b> la règle 5 (refus de SSH depuis any) est placée avant la règle 6 : les administrateurs ne peuvent jamais administrer le serveur web en SSH. Il faut <b>placer la règle 6 avant la règle 5</b> (la règle la plus précise d'abord).</p>" : "<p>La règle 7 est la <b>politique par défaut « tout refuser »</b> : tout flux non explicitement autorisé est bloqué (principe du moindre privilège appliqué au réseau).</p>"}` };
}});

/* ---------- 4. Matrice de risques */
G.push({ titre: "Placer des risques dans la matrice", niv: 2, ch: 1, gen() {
  const base = [["Ransomware sur le serveur de fichiers (pas de sauvegarde hors ligne)", 4, 3], ["Panne du disque d'un poste de l'accueil", 1, 3], ["Vol d'un portable non chiffré contenant le fichier clients", 3, 2], ["DDoS sur le site vitrine (sans vente en ligne)", 1, 2], ["Phishing ciblant les comptables (virements)", 3, 3], ["Incendie de la salle serveur unique", 4, 1], ["Fuite de données de santé par un partage mal configuré", 4, 2], ["Accès au Wi-Fi invité par un voisin", 1, 4], ["Compromission du VPN non mis à jour (CVE critique publiée)", 4, 4], ["Erreur de manipulation d'un stagiaire sur la base produits", 2, 3]];
  const sel = shuf(base).slice(0, 4);
  const niveau = (g, v) => { const p = g * v; return p >= 9 || (g === 4 && v >= 2) ? "élevé" : p >= 4 ? "moyen" : "faible"; };
  const trait = n => n === "élevé" ? "<b>réduire</b> en priorité (mesures techniques et organisationnelles), éventuellement <b>transférer</b> le reste" : n === "moyen" ? "<b>réduire</b> avec des mesures proportionnées, planifiées" : "<b>accepter</b> (ou mesures simples et peu coûteuses)";
  return { q: `<p>Échelles : gravité de 1 (mineure) à 4 (critique), vraisemblance de 1 (minime) à 4 (maximale). Niveau : produit ≥ 9 ou gravité 4 avec vraisemblance ≥ 2 → élevé ; produit de 4 à 8 → moyen ; sinon faible.</p>${T(["Risque", "Gravité", "Vraisemblance"], sel.map(r => [r[0], r[1], r[2]]))}<ol><li>Calculez le niveau de chaque risque et classez-les.</li><li>Proposez un traitement pour chacun.</li></ol>`,
    c: T(["Risque", "G × V", "Niveau", "Traitement"], sel.slice().sort((a, b) => b[1] * b[2] - a[1] * a[2]).map(r => [r[0], `${r[1]} × ${r[2]} = ${r[1] * r[2]}`, niveau(r[1], r[2]), trait(niveau(r[1], r[2]))])) + "<p>On traite d'abord les risques élevés. Le risque résiduel (après mesures) est réévalué et accepté formellement par la direction.</p>" };
}});

/* ---------- 5. RAID */
G.push({ titre: "Calculer une capacité RAID", niv: 1, ch: 8, gen() {
  const type = pick(["RAID 0", "RAID 1", "RAID 5", "RAID 6", "RAID 10"]);
  const n = type === "RAID 1" ? 2 : type === "RAID 10" ? pick([4, 6, 8]) : type === "RAID 6" ? R(4, 8) : type === "RAID 5" ? R(3, 8) : R(2, 6);
  const t = pick([1, 2, 4, 8, 12, 16]);
  const util = { "RAID 0": n * t, "RAID 1": t, "RAID 5": (n - 1) * t, "RAID 6": (n - 2) * t, "RAID 10": n * t / 2 }[type];
  const tol = { "RAID 0": "aucune : la perte d'un disque fait perdre toutes les données", "RAID 1": "1 disque", "RAID 5": "1 disque", "RAID 6": "2 disques", "RAID 10": "1 disque par paire miroir (jusqu'à " + n / 2 + " si ce ne sont pas les deux disques d'une même paire)" }[type];
  return { q: `<p>Un NAS est configuré en <b>${type}</b> avec <b>${n} disques de ${t} To</b>.</p><ol><li>Quelle est la capacité utile ?</li><li>Combien de disques peuvent tomber en panne sans perte de données ?</li><li>Ce RAID remplace-t-il une sauvegarde ?</li></ol>`,
    c: `<ol><li>Capacité utile : <b>${util} To</b> sur ${n * t} To bruts (${{ "RAID 0": "n × t", "RAID 1": "t", "RAID 5": "(n − 1) × t", "RAID 6": "(n − 2) × t", "RAID 10": "n × t / 2" }[type]}), soit ${Math.round(util / (n * t) * 100)} % d'efficacité.</li><li>Tolérance : <b>${tol}</b>.</li><li><b>Non</b> : le RAID protège contre la panne matérielle (disponibilité) mais une suppression, une corruption ou un ransomware est répliqué sur tous les disques. Il faut une vraie sauvegarde (3-2-1, copie hors ligne).</li></ol>` };
}});

/* ---------- 6. RPO / sauvegardes */
G.push({ titre: "Sauvegardes, RPO et restauration", niv: 2, ch: 8, gen() {
  const jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"];
  const type = pick(["incrémentale", "différentielle"]);
  const hS = pick([20, 21, 22, 23]), jIncident = R(2, 5), hIncident = pick([10, 11, 14, 15, 16]);
  const jComplete = 6;
  const restau = type === "incrémentale" ? `la complète de dimanche, puis <b>toutes les incrémentales</b> de lundi à ${jours[jIncident - 1]} (${jIncident} sauvegardes), dans l'ordre` : `la complète de dimanche, puis <b>la seule différentielle</b> de ${jours[jIncident - 1]}`;
  const perte = 24 - hS + hIncident;
  return { q: `<p>Une entreprise fait une sauvegarde <b>complète le dimanche</b> à ${hS} h et une sauvegarde <b>${type}</b> chaque soir du lundi au samedi à ${hS} h. Le <b>${jours[jIncident]} à ${hIncident} h</b>, un ransomware chiffre le serveur.</p><ol><li>Quelles sauvegardes faut-il restaurer, et dans quel ordre ?</li><li>Quelle quantité de travail est perdue ? Quel est le RPO de cette stratégie ?</li><li>La direction exige un RPO de 4 heures. Que proposez-vous ?</li></ol>`,
    c: `<ol><li>Restaurer ${restau}. ${type === "incrémentale" ? "Restauration plus longue et fragile (si une incrémentale est corrompue, la suite est inutilisable)." : "Restauration plus simple, mais chaque différentielle grossit au fil de la semaine."}</li><li>Perte : le travail depuis ${jours[jIncident - 1]} ${hS} h jusqu'à ${jours[jIncident]} ${hIncident} h, soit <b>${perte} heures</b>. Le <b>RPO</b> de cette stratégie est de <b>24 heures</b> (une sauvegarde par jour).</li><li>Sauvegarder plus souvent : <b>clichés (snapshots)</b> toutes les heures ou toutes les 4 h, ou <b>réplication</b> continue vers un second serveur, en gardant une copie <b>hors ligne/immuable</b> (sinon le ransomware peut toucher aussi les copies). Vérifier que les sauvegardes sont saines avant restauration.</li></ol>` };
}});

/* ---------- 7. CVSS */
G.push({ titre: "Lire une alerte de vulnérabilité", niv: 1, ch: 3, gen() {
  const prod = pick([["la passerelle VPN SSL", true], ["le serveur web Apache de la DMZ", true], ["le logiciel de comptabilité interne", false], ["l'hyperviseur VMware", false], ["le pare-feu périmétrique", true], ["le client de messagerie des postes", false]]);
  const score = pick([3.1, 4.3, 5.4, 6.5, 7.2, 7.5, 8.1, 8.8, 9.1, 9.8, 10]);
  const sev = score >= 9 ? "critique" : score >= 7 ? "élevée" : score >= 4 ? "moyenne" : "faible";
  const auth = pick([true, false]);
  const annee = pick([2024, 2025, 2026]);
  const cve = `CVE-${annee}-${R(10000, 49999)}`;
  const urgent = sev === "critique" || (sev === "élevée" && prod[1]);
  return { q: `<p>Le CERT-FR publie un avis : <b>${cve}</b> affecte ${prod[0]} de votre organisation. Score <b>CVSS ${fr(score)}</b>, exploitable ${prod[1] ? "à distance depuis Internet" : "depuis le réseau interne"}, ${auth ? "<b>sans authentification</b>" : "avec un compte utilisateur"}.</p><ol><li>Que signifient CVE et CVSS ? Quelle est la sévérité ?</li><li>Quelle priorité donnez-vous et quelles actions ?</li></ol>`,
    c: `<ol><li>La <b>CVE</b> est l'identifiant public de la vulnérabilité (${annee} = année d'enregistrement). Le <b>CVSS</b> note sa gravité de 0 à 10 : ${fr(score)} → sévérité <b>${sev}</b>.</li><li>${urgent ? `<b>Priorité maximale</b> : l'équipement est ${prod[1] ? "exposé sur Internet" : "central"}${auth ? " et l'attaque ne demande aucune authentification" : ""}. Appliquer le correctif sans attendre (fenêtre de maintenance d'urgence) ; à défaut, appliquer le contournement de l'éditeur ou isoler le service ; vérifier les journaux pour détecter une exploitation passée.` : `Priorité ${sev === "élevée" ? "haute" : "normale"} : planifier le correctif dans le cycle de mises à jour (${sev === "faible" ? "prochaine maintenance" : "sous quelques jours"}), en tenant compte de l'exposition (${prod[1] ? "Internet : accélérer" : "réseau interne seulement"}).`} Tester le correctif, documenter, et tenir l'inventaire à jour pour savoir rapidement quels équipements sont concernés.</li></ol>` };
}});

/* ---------- 8. Entropie mot de passe */
G.push({ titre: "Robustesse d'un mot de passe", niv: 2, ch: 5, gen() {
  const alph = pick([[10, "chiffres uniquement"], [26, "minuscules uniquement"], [36, "minuscules et chiffres"], [62, "minuscules, majuscules et chiffres"], [90, "minuscules, majuscules, chiffres et caractères spéciaux"]]);
  const L = pick([6, 8, 10, 12, 14, 16]);
  const bits = L * Math.log2(alph[0]);
  const vit = pick([1e9, 1e10, 1e11]);
  const sec = Math.pow(2, bits) / vit / 2;
  const dur = sec < 60 ? `${fr(sec, 2)} secondes` : sec < 3600 ? `${fr(sec / 60, 0)} minutes` : sec < 86400 ? `${fr(sec / 3600, 1)} heures` : sec < 31536000 ? `${fr(sec / 86400, 0)} jours` : sec < 31536000 * 1e6 ? `${fr(sec / 31536000, 0)} ans` : `plus d'un million d'années`;
  const nivF = bits < 64 ? "très faible" : bits < 80 ? "faible" : bits < 100 ? "moyenne" : "forte";
  return { q: `<p>Un mot de passe de <b>${L} caractères</b> est choisi au hasard parmi les <b>${alph[1]}</b> (${alph[0]} symboles possibles). Un attaquant teste <b>${vit.toExponential().replace("e+", " × 10^")}</b> combinaisons par seconde sur une empreinte volée.</p><ol><li>Calculez l'entropie en bits (L × log₂ N).</li><li>Estimez le temps moyen pour le trouver (la moitié des combinaisons).</li><li>Comparez aux recommandations (ANSSI : au moins 80 bits pour une sécurité moyenne, 100 bits pour une sécurité forte).</li></ol>`,
    c: `<ol><li>Entropie = ${L} × log₂(${alph[0]}) ≈ ${L} × ${fr(Math.log2(alph[0]), 2)} ≈ <b>${fr(bits, 0)} bits</b>.</li><li>Nombre de combinaisons : 2<sup>${fr(bits, 0)}</sup> ≈ ${Math.pow(2, bits).toExponential(1).replace("e+", " × 10^")}. Temps moyen ≈ 2<sup>${fr(bits, 0)}</sup> / 2 / ${vit.toExponential().replace("e+", " × 10^")} ≈ <b>${dur}</b>.</li><li>Robustesse <b>${nivF}</b>. ${bits < 80 ? "Insuffisant : allonger le mot de passe (la longueur compte plus que la complexité), ou utiliser une phrase de passe, et ajouter le MFA. Le stockage doit être haché et salé avec une fonction lente pour ralentir l'attaquant." : "Correct, à condition que le mot de passe soit vraiment aléatoire (pas un mot du dictionnaire) et unique ; le MFA reste recommandé."}</li></ol>` };
}});

/* ---------- 9. DICP */
G.push({ titre: "Classer des incidents selon DICP", niv: 1, ch: 0, gen() {
  const sc = shuf([["Le serveur de messagerie est saturé et ne répond plus", "D"], ["Un ancien salarié consulte encore les fiches de paie depuis chez lui", "C"], ["Le montant d'une facture a été modifié dans la base sans trace", "I et P"], ["Les journaux de connexion ne sont pas conservés", "P"], ["Un ransomware chiffre le partage commun", "D (et I)"], ["Un e-mail contenant la liste des clients est envoyé au mauvais destinataire", "C"], ["Une coupure électrique arrête la salle serveur", "D"], ["Un attaquant intercepte les identifiants sur un Wi-Fi public non chiffré", "C"], ["Un site web est défiguré (page d'accueil remplacée)", "I"], ["Plusieurs techniciens partagent le compte « admin »", "P"]]).slice(0, 5);
  return { q: `<p>Pour chaque situation, indiquez le critère DICP principalement atteint et proposez une mesure :</p><ol>${sc.map(s => `<li>${s[0]}</li>`).join("")}</ol>`,
    c: T(["Situation", "Critère"], sc.map(s => [s[0], `<b>${s[1]}</b>`])) + "<p>Mesures possibles : redondance et sauvegardes (D) ; contrôle d'accès, procédure de départ, chiffrement (C) ; contrôle d'intégrité, droits limités, hachage (I) ; comptes nominatifs et journalisation centralisée (P).</p>" };
}});

/* ---------- 10. Crypto : quelle clé ? */
G.push({ titre: "Choisir la clé et le mécanisme", niv: 2, ch: 4, gen() {
  const [a, b] = shuf(["Alice", "Bob", "Chloé", "Damien", "Emma"]).slice(0, 2);
  const cas = shuf([
    [`${a} veut envoyer à ${b} un fichier que seul ${b} pourra lire.`, `Chiffrer avec la <b>clé publique de ${b}</b> ; ${b} déchiffre avec sa clé privée. En pratique : une clé AES aléatoire chiffre le fichier, et cette clé est chiffrée avec la clé publique de ${b} (chiffrement hybride).`],
    [`${a} veut prouver à ${b} qu'elle est bien l'auteure d'un document et qu'il n'a pas été modifié.`, `<b>Signer</b> : hacher le document puis chiffrer l'empreinte avec la <b>clé privée de ${a}</b>. ${b} vérifie avec la <b>clé publique de ${a}</b> (garantie par son certificat). Apporte intégrité, authenticité et non-répudiation.`],
    [`${b} veut vérifier qu'une ISO téléchargée est intacte.`, `Calculer son empreinte <b>SHA-256</b> et la comparer à celle publiée par l'éditeur (idéalement elle-même signée).`],
    [`Le serveur doit stocker les mots de passe de ${a} et ${b}, qui ont choisi le même.`, `<b>Hachage salé</b> avec une fonction lente (Argon2, bcrypt) : grâce au sel, les deux empreintes sont différentes.`],
    [`Deux agences veulent chiffrer tout le trafic qui transite entre elles par Internet.`, `<b>VPN IPsec site à site</b> : échange de clés asymétrique (IKE), puis chiffrement symétrique (AES) du trafic.`],
    [`${a} se connecte au site de sa banque et veut être sûre de parler au vrai serveur.`, `<b>TLS</b> : le serveur présente un <b>certificat</b> signé par une autorité de certification reconnue ; le navigateur vérifie la chaîne de confiance, le nom de domaine et la validité.`],
  ]).slice(0, 3);
  return { q: `<p>Pour chaque besoin, précisez le mécanisme cryptographique et la clé utilisée :</p><ol>${cas.map(c => `<li>${c[0]}</li>`).join("")}</ol>`, c: `<ol>${cas.map(c => `<li>${c[1]}</li>`).join("")}</ol>` };
}});

/* ---------- 11. Sous-réseaux / VLAN */
G.push({ titre: "Plan d'adressage par VLAN", niv: 2, ch: 6, gen() {
  const services = shuf([["Administration", R(5, 12)], ["Serveurs", R(8, 25)], ["Comptabilité", R(10, 28)], ["Production", R(40, 110)], ["Wi-Fi invités", R(60, 200)], ["Téléphonie IP", R(20, 55)], ["Vidéosurveillance", R(10, 28)]]).slice(0, 4);
  const masque = n => { let h = 2; while (Math.pow(2, h) - 2 < n) h++; return 32 - h; };
  const sorted = services.slice().sort((x, y) => masque(x[1]) - masque(y[1]));
  let base = 0;
  const lignes = sorted.map((s, i) => { const cidr = masque(s[1]), taille = Math.pow(2, 32 - cidr); const r = [`VLAN ${(i + 1) * 10} – ${s[0]}`, s[1], `/${cidr}`, `10.20.${Math.floor(base / 256)}.${base % 256}`, Math.pow(2, 32 - cidr) - 2]; base += taille; return r; });
  return { q: `<p>On découpe le réseau <b>10.20.0.0/22</b> en VLAN. Besoins en adresses (équipements + passerelle) :</p>${T(["Service", "Hôtes"], services)}<ol><li>Donnez pour chaque VLAN le masque le plus adapté et l'adresse de réseau (en commençant par le plus grand).</li><li>Pourquoi segmenter en VLAN du point de vue de la sécurité ? Comment filtrer entre VLAN ?</li></ol>`,
    c: `${T(["VLAN", "Besoin", "Masque", "Adresse réseau", "Hôtes possibles"], lignes)}<p>Le masque est le plus petit bloc tel que 2<sup>h</sup> − 2 ≥ besoin (h = bits d'hôte).</p><p><b>Sécurité :</b> cloisonnement (un poste compromis ne voit pas tout le réseau), réduction de la surface d'attaque, isolement des invités et des équipements peu sûrs (caméras, IoT), application de règles différentes par zone. Le <b>routage inter-VLAN</b> passe par le pare-feu ou un switch de niveau 3 avec des <b>ACL</b> : on n'autorise que les flux nécessaires (par exemple Comptabilité → Serveurs sur le port applicatif), le reste est refusé.</p>` };
}});

/* ---------- 12. RGPD : est-ce une donnée personnelle / sensible ? */
G.push({ titre: "Données personnelles ou non ?", niv: 1, ch: 2, gen() {
  const d = shuf([["l'adresse e-mail prenom.nom@entreprise.fr", "personnelle"], ["l'adresse IP d'un visiteur du site", "personnelle (identification indirecte)"], ["le chiffre d'affaires annuel de l'entreprise", "non personnelle"], ["le groupe sanguin d'un salarié", "sensible (santé)"], ["la plaque d'immatriculation d'un véhicule", "personnelle"], ["l'appartenance syndicale d'un salarié", "sensible"], ["la température de la salle serveur", "non personnelle"], ["l'empreinte digitale pour la badgeuse", "sensible (biométrique)"], ["un numéro de client « C-48211 »", "personnelle (identification indirecte)"], ["des statistiques anonymisées de fréquentation", "non personnelle si l'anonymisation est irréversible"], ["la religion déclarée pour un repas", "sensible"]]).slice(0, 6);
  return { q: `<p>Classez chaque donnée : non personnelle, personnelle ou sensible.</p><ol>${d.map(x => `<li>${x[0]}</li>`).join("")}</ol><p>Que change le caractère sensible d'une donnée ?</p>`,
    c: `${T(["Donnée", "Catégorie"], d.map(x => [x[0], `<b>${x[1]}</b>`]))}<p>Les données sensibles sont <b>interdites de traitement par principe</b>, sauf exception (consentement explicite, obligation légale…), demandent une sécurité renforcée et souvent une <b>AIPD</b>. Une donnée pseudonymisée (numéro client) reste personnelle ; seule une anonymisation irréversible la fait sortir du RGPD.</p>` };
}});

/* ---------- 13. SPF/DMARC : lire un enregistrement */
G.push({ titre: "Lire SPF et DMARC", niv: 2, ch: 9, gen() {
  const dom = pick(["vitalis-sante.fr", "garage-morel.fr", "mairie-valmont.fr", "transports-rapido.fr"]);
  const ipOk = `203.0.113.${R(2, 60)}`, ipTest = pick([ipOk, `198.51.100.${R(2, 200)}`]);
  const qual = pick(["-all", "~all"]), pol = pick(["none", "quarantine", "reject"]);
  const passe = ipTest === ipOk;
  return { q: `<p>Enregistrements DNS du domaine <b>${dom}</b> :</p><pre class="log">${dom}.        TXT  "v=spf1 ip4:${ipOk} include:_spf.mailpro.fr ${qual}"\n_dmarc.${dom}. TXT  "v=DMARC1; p=${pol}; rua=mailto:dmarc@${dom}"</pre><p>Un e-mail « From: comptabilite@${dom} » arrive depuis le serveur <b>${ipTest}</b> (qui n'est pas un serveur de mailpro.fr) et n'a pas de signature DKIM valide.</p><ol><li>Que dit l'enregistrement SPF ? Le contrôle SPF passe-t-il ?</li><li>Que fera le serveur destinataire d'après DMARC ?</li><li>Que recommandez-vous ?</li></ol>`,
    c: `<ol><li>SPF autorise ${ipOk} et les serveurs de mailpro.fr ; <code>${qual}</code> signifie ${qual === "-all" ? "« refuser tout le reste » (échec strict)" : "« échec léger » (softfail : accepté mais marqué suspect)"}. Ici le contrôle SPF ${passe ? "<b>passe</b> (l'IP est autorisée)" : "<b>échoue</b> : l'IP n'est pas autorisée"}.</li><li>${passe ? "DMARC est satisfait car SPF passe et le domaine est aligné : le message est délivré (attention : si ce serveur légitime est compromis, SPF ne protège pas)." : `SPF et DKIM échouent, donc DMARC échoue : avec <code>p=${pol}</code>, le destinataire ${pol === "none" ? "<b>délivre quand même</b> le message et envoie seulement un rapport" : pol === "quarantine" ? "place le message en <b>quarantaine</b> (spam)" : "<b>rejette</b> le message"}.`}</li><li>Activer <b>DKIM</b> sur les serveurs d'envoi ; ${pol !== "reject" ? `faire évoluer DMARC vers <code>p=reject</code> après analyse des rapports ; ` : ""}${qual === "~all" ? "passer SPF en <code>-all</code> ; " : ""}surveiller les rapports <code>rua</code> ; sensibiliser les salariés à l'usurpation.</li></ol>` };
}});

/* ---------- 14. Incident : remettre les étapes dans l'ordre */
G.push({ titre: "Gérer un incident étape par étape", niv: 1, ch: 7, gen() {
  const inc = pick([["un ransomware sur un poste du service RH", ["Débrancher le câble réseau du poste (sans l'éteindre)", "Supprimer le logiciel malveillant ou réinstaller le poste, corriger la faille d'entrée", "Restaurer les fichiers depuis une sauvegarde saine", "Analyser l'incident en réunion et mettre à jour les procédures"]], ["un compte administrateur utilisé la nuit depuis une IP étrangère", ["Désactiver le compte et bloquer l'IP sur le pare-feu", "Supprimer les comptes et tâches planifiées créés par l'attaquant, réinitialiser les mots de passe", "Remettre les services en production sous surveillance renforcée", "Rédiger le retour d'expérience et déployer le MFA"]], ["un serveur web défiguré", ["Retirer le site du réseau (page de maintenance)", "Corriger la vulnérabilité exploitée et nettoyer le serveur", "Redéployer le site depuis une version saine", "Documenter l'incident et planifier un audit"]]]);
  const etapes = ["Contenir", "Éradiquer", "Restaurer", "RETEX"];
  const desordre = shuf(inc[1].map((a, i) => [a, i]));
  return { q: `<p>Incident : <b>${inc[0]}</b>, détecté par une alerte du SIEM. Remettez les actions dans l'ordre et associez-les aux étapes de gestion d'incident :</p><ul>${desordre.map(x => `<li>${x[0]}</li>`).join("")}</ul><p>Quelles obligations légales vérifier ?</p>`,
    c: `<ol>${inc[1].map((a, i) => `<li><b>${etapes[i]}</b> : ${a}</li>`).join("")}</ol><p>Avant tout : <b>détecter et qualifier</b> (c'est fait par le SIEM). Conserver les <b>preuves</b> (journaux, image disque). <b>Obligations :</b> si des données personnelles sont touchées, notifier la <b>CNIL sous 72 h</b> (et informer les personnes si le risque est élevé) ; déposer <b>plainte</b> ; prévenir l'assureur ; si l'organisation est soumise à NIS2, notifier l'ANSSI.</p>` };
}});
})();
