/* ==========================================================================
   Révisions E7 Cybersécurité SISR — moteur du site
   Le contenu est dans data/cyber.js (objet COURS).
   ========================================================================== */
{
const app = document.getElementById("app"), m = COURS;
const store = {
  get(k, d) { try { const v = localStorage.getItem("cyber-" + k); return v ? JSON.parse(v) : d; } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem("cyber-" + k, JSON.stringify(v)); } catch (e) {} }
};
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const { R, shuf } = OUT;
const NIV = { 1: "Facile", 2: "Moyen", 3: "Type examen" };
const TABS = [["accueil", "Accueil"], ["fiches", "Fiches"], ["exos", "Exercices"], ["quiz", "Quiz"], ["methode", "Méthode"], ["sujets", "Sujets type E7"], ["vocab", "Lexique"]];
const s = { fiche: store.get("fiche", 0), exCh: "all", exLvl: "all", quiz: null, vTheme: 0, vSens: "ab" };
const nom = c => c.court || c.titre;

document.getElementById("navlinks").innerHTML = TABS.map(([k, l]) => `<a href="#${k}">${l}</a>`).join("");
function route() {
  const h = location.hash.slice(1), tab = TABS.some(t => t[0] === h) ? h : "accueil";
  document.querySelectorAll("#navlinks a").forEach(a => a.getAttribute("href") === "#" + tab ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  app.innerHTML = tab === "accueil" ? "" : `<header class="mhead"><p class="eyebrow">${m.sous}</p><h1>${TABS.find(t => t[0] === tab)[1]}</h1></header>`;
  const pane = document.createElement("div"); app.appendChild(pane);
  ({ accueil, fiches, exos, quiz, methode, sujets, vocab })[tab](pane);
}
window.addEventListener("hashchange", () => { route(); window.scrollTo(0, 0); });

/* ---- accueil */
function accueil(el) {
  const lus = store.get("lu", []), best = store.get("best", {});
  const q = m.chapitres.map((_, i) => best[i]).filter(v => v != null);
  const nbEx = m.chapitres.reduce((a, c) => a + c.exos.length, 0);
  el.innerHTML = `
    <div class="hero">
      <p class="eyebrow">${m.sous}</p>
      <h1>${m.titreAccueil}</h1>
      <p class="lead">${m.intro}</p>
      <div class="row center" style="margin-top:24px"><a class="btn" href="#exos">Tirer des exercices</a><a class="btn ghost" href="#fiches">Lire les fiches</a></div>
      <div class="stats">
        <div class="card"><span class="stat">${lus.length}/${m.chapitres.length}</span><small>fiches lues</small></div>
        <div class="card"><span class="stat">${q.length ? Math.round(q.reduce((a, b) => a + b, 0) / q.length) + " %" : "—"}</span><small>moyenne aux quiz</small></div>
        <div class="card"><span class="stat">${nbEx} + ∞</span><small>exercices rédigés + générés</small></div>
      </div>
    </div>
    <details class="epreuve" open><summary>L'épreuve en bref</summary><div>${m.epreuve}</div></details>
    <h2 style="text-align:center;margin-top:48px">Les ${m.chapitres.length} thèmes à maîtriser</h2>
    <div class="grid chap-grid">${m.chapitres.map((c, i) => `<a class="card mat" href="#fiches" data-i="${i}"><p class="num">Thème ${i + 1}${lus.includes(i) ? " · ✓ lu" : ""}</p><h3>${c.titre}</h3><p>${c.resume}</p>${best[i] != null ? `<p class="count">Quiz : ${best[i]} %</p>` : ""}</a>`).join("")}</div>`;
  el.querySelector(".chap-grid").onclick = e => { const a = e.target.closest("a[data-i]"); if (a) { s.fiche = +a.dataset.i; store.set("fiche", s.fiche); } };
}

/* ---- fiches */
function fiches(el) {
  const i = Math.min(s.fiche, m.chapitres.length - 1), c = m.chapitres[i], lus = store.get("lu", []);
  el.innerHTML = `<div class="layout">
    <div class="side">${m.chapitres.map((x, k) => `<button class="chip" type="button" data-i="${k}" aria-pressed="${k === i}">${lus.includes(k) ? "✓ " : ""}${k + 1}. ${nom(x)}</button>`).join("")}</div>
    <article class="card fiche on"><p class="eyebrow">Thème ${i + 1}</p><h2>${c.titre}</h2>${c.fiche}
      <label class="lu"><input type="checkbox" id="lu" ${lus.includes(i) ? "checked" : ""}> J'ai lu et compris cette fiche</label>
      <div class="row" style="margin-top:14px"><button class="btn" type="button" id="goEx">S'entraîner sur ce thème</button><button class="btn ghost" type="button" id="goQz">Faire le quiz</button></div>
    </article></div>`;
  el.querySelector(".side").onclick = e => { const b = e.target.closest(".chip"); if (b) { s.fiche = +b.dataset.i; store.set("fiche", s.fiche); fiches(el); window.scrollTo({ top: 0 }); } };
  el.querySelector("#lu").onchange = e => { const L = new Set(lus); e.target.checked ? L.add(i) : L.delete(i); store.set("lu", [...L]); fiches(el); };
  el.querySelector("#goEx").onclick = () => { s.exCh = i; location.hash = "exos"; };
  el.querySelector("#goQz").onclick = () => { s.quiz = i; location.hash = "quiz"; };
}

/* ---- exercices tirés au hasard */
function exos(el) {
  el.innerHTML = `
    <div class="chips" id="exCh"><button class="chip" type="button" data-c="all">Tout le programme</button>${m.chapitres.map((c, k) => `<button class="chip" type="button" data-c="${k}">${nom(c)}</button>`).join("")}</div>
    <div class="row center exctl">
      <div class="chips" id="exLvl">${[["all", "Tous niveaux"], ["1", "Facile"], ["2", "Moyen"], ["3", "Type examen"]].map(([v, l]) => `<button class="chip small" type="button" data-l="${v}">${l}</button>`).join("")}</div>
      <label class="cnt">Nombre <select id="exN"><option>3</option><option selected>5</option><option>8</option></select></label>
      <button class="btn" type="button" id="exGo">Nouvelle série</button>
    </div>
    <p class="exinfo" id="exInfo"></p><div id="exList"></div>`;
  const draw = () => {
    el.querySelectorAll("#exCh .chip").forEach(b => b.setAttribute("aria-pressed", b.dataset.c === String(s.exCh)));
    el.querySelectorAll("#exLvl .chip").forEach(b => b.setAttribute("aria-pressed", b.dataset.l === String(s.exLvl)));
    const n = +el.querySelector("#exN").value, okL = e => s.exLvl === "all" || e.niv === +s.exLvl, okC = k => s.exCh === "all" || k === +s.exCh;
    const ecrits = m.chapitres.flatMap((c, k) => okC(k) ? c.exos.map(e => ({ ...e, ch: k })) : []).filter(okL);
    const generes = m.generes.filter(g => (g.ch == null || okC(g.ch)) && okL(g));
    let seen = store.get("seen", []), reset = false;
    const wantE = generes.length ? Math.min(Math.ceil(n * 0.5), ecrits.length) : Math.min(n, ecrits.length);
    let unseen = ecrits.filter(e => !seen.includes(e.id));
    if (unseen.length < wantE) { seen = seen.filter(id => !ecrits.some(e => e.id === id)); unseen = ecrits; reset = true; }
    const chosen = shuf(unseen).slice(0, wantE), serie = chosen.map(e => ({ ...e, alea: false }));
    const gens = shuf(generes); let k = 0;
    while (serie.length < n && gens.length && k < Math.min(n, gens.length * 2)) { const g = gens[k++ % gens.length], x = g.gen(); serie.push({ titre: g.titre, niv: g.niv, ch: g.ch, q: x.q, c: x.c, alea: true }); }
    const rest = shuf(ecrits.filter(e => !chosen.includes(e)));
    while (serie.length < n && rest.length) serie.push({ ...rest.pop(), alea: false });
    if (serie.length < n && (s.exLvl === "all" || s.exLvl === "1")) {
      const qc = shuf(m.chapitres.flatMap((c, k) => okC(k) ? c.quiz.map(z => ({ z, k })) : []));
      while (serie.length < n && qc.length) { const { z, k } = qc.pop(); serie.push({ titre: "Question de cours", niv: 1, ch: k, q: z[0], c: `<p><b>${z[1][0]}</b></p><p>${z[2]}</p>`, alea: true }); }
    }
    serie.sort((a, b) => a.niv - b.niv);
    store.set("seen", [...new Set([...seen, ...chosen.map(e => e.id)])]);
    const tot = m.chapitres.reduce((a, c) => a + c.exos.length, 0);
    el.querySelector("#exInfo").innerHTML = `${tot} exercices rédigés et ${m.generes.length} modèles générés au hasard (logs, pare-feu, risques, RAID…). Tu as déjà vu ${store.get("seen", []).length} exercices rédigés.` + (reset ? " <b>Tu as fait le tour de cette sélection : le tirage recommence.</b>" : "");
    el.querySelector("#exList").innerHTML = serie.map((x, i) => `
      <article class="card exo"><div class="exo-head"><h3>Exercice ${i + 1} · ${x.titre}</h3><div class="badges"><span class="lvl l${x.niv}">${NIV[x.niv]}</span>${x.alea ? `<span class="lvl alea">Généré</span>` : ""}</div></div>
      ${x.ch != null ? `<p class="exch">${nom(m.chapitres[x.ch])}</p>` : ""}
      <div class="q">${x.q}</div><details class="corr"><summary>Voir la correction</summary><div class="sol">${x.c}</div></details></article>`).join("")
      + `<div class="row center" style="margin-top:22px"><button class="btn" type="button" id="exAgain">Nouvelle série</button></div>`;
    el.querySelector("#exAgain").onclick = () => { draw(); window.scrollTo({ top: 0, behavior: "smooth" }); };
  };
  el.querySelector("#exCh").onclick = e => { const b = e.target.closest(".chip"); if (b) { s.exCh = b.dataset.c === "all" ? "all" : +b.dataset.c; draw(); } };
  el.querySelector("#exLvl").onclick = e => { const b = e.target.closest(".chip"); if (b) { s.exLvl = b.dataset.l; draw(); } };
  el.querySelector("#exGo").onclick = draw; el.querySelector("#exN").onchange = draw;
  draw();
}

/* ---- quiz */
function quiz(el) {
  const best = store.get("best", {});
  el.innerHTML = `<div class="chips" id="qzCh">${m.chapitres.map((c, k) => `<button class="chip" type="button" data-c="${k}">${nom(c)}${best[k] != null ? ` · ${best[k]} %` : ""}</button>`).join("")}<button class="chip" type="button" data-c="mix">Mélange de 15 questions</button></div>
    <div class="card" id="qzBox" style="max-width:760px;margin:0 auto"><p>Choisis un thème pour commencer, ou fais le mélange.</p></div>`;
  const box = el.querySelector("#qzBox");
  let qs = [], qi = 0, ok = 0, ch = null;
  const start = c => { ch = c; qi = 0; ok = 0; qs = c === "mix" ? shuf(m.chapitres.flatMap(x => x.quiz)).slice(0, 15) : shuf(m.chapitres[c].quiz); el.querySelectorAll("#qzCh .chip").forEach(b => b.setAttribute("aria-pressed", b.dataset.c === String(c))); show(); };
  const show = () => {
    if (qi >= qs.length) return end();
    const [q, opts, ex] = qs[qi], o = shuf(opts.map((t, k) => ({ t, good: k === 0 })));
    box.innerHTML = `<div class="qhead"><span>${ch === "mix" ? "Mélange" : esc(nom(m.chapitres[ch]))}</span><span>Question ${qi + 1} / ${qs.length} · ${ok} bonne(s)</span></div><div class="prog"><i style="width:${100 * qi / qs.length}%"></i></div><h3>${q}</h3><div class="opts">${o.map((x, k) => `<button class="opt" type="button" data-k="${k}">${x.t}</button>`).join("")}</div><div class="fb" id="qFb"></div>`;
    box.querySelectorAll(".opt").forEach(b => b.onclick = () => {
      const k = +b.dataset.k, good = o[k].good; if (good) ok++;
      box.querySelectorAll(".opt").forEach((bb, j) => { bb.disabled = true; if (o[j].good) bb.classList.add("good"); else if (j === k) bb.classList.add("bad"); });
      const fb = box.querySelector("#qFb"); fb.className = "fb " + (good ? "ok" : "ko");
      fb.innerHTML = `<b>${good ? "Bonne réponse !" : "Raté."}</b><span>${ex}</span><button class="btn" type="button" id="qNx" style="margin-top:10px">${qi + 1 < qs.length ? "Question suivante" : "Voir mon score"}</button>`;
      const nx = box.querySelector("#qNx"); nx.onclick = () => { qi++; show(); }; nx.focus();
    });
  };
  const end = () => {
    const pct = Math.round(100 * ok / qs.length);
    if (ch !== "mix") { const b = store.get("best", {}); b[ch] = Math.max(b[ch] || 0, pct); store.set("best", b); }
    box.innerHTML = `<div class="stat">${ok} / ${qs.length}</div><p>${pct >= 80 ? "Excellent, c'est maîtrisé." : pct >= 50 ? "Pas mal ! Relis la fiche pour combler les trous." : "Relis la fiche, puis recommence."}</p><div class="row"><button class="btn" type="button" id="qAg">Recommencer</button>${ch !== "mix" ? `<button class="btn ghost" type="button" id="qFi">Revoir la fiche</button>` : ""}</div>`;
    box.querySelector("#qAg").onclick = () => start(ch);
    const f = box.querySelector("#qFi"); if (f) f.onclick = () => { s.fiche = ch; location.hash = "fiches"; };
  };
  el.querySelector("#qzCh").onclick = e => { const b = e.target.closest(".chip"); if (b) start(b.dataset.c === "mix" ? "mix" : +b.dataset.c); };
  if (s.quiz != null) { start(s.quiz); s.quiz = null; }
}

/* ---- méthode */
function methode(el) { el.innerHTML = `<div class="stack">${m.methode.map((x, k) => `<details class="card meth" ${k === 0 ? "open" : ""}><summary><h3>${x.titre}</h3></summary><div>${x.html}</div></details>`).join("")}</div>`; }

/* ---- sujets type E7 */
function sujets(el) {
  el.innerHTML = `<p class="exinfo">Ces cas ont été écrits pour l'entraînement, au format de l'épreuve E7 : un contexte, des dossiers avec barème et des documents. Fais-les en temps limité, puis compare avec le corrigé.</p>
    <div class="stack">${m.sujets.map((x, k) => `<article class="card exo"><div class="exo-head"><h3>Cas ${k + 1} · ${x.titre}</h3><div class="badges"><span class="lvl l3">${x.type}</span></div></div><div class="q">${x.q}</div><details class="corr"><summary>Voir le corrigé</summary><div class="sol">${x.c}</div></details></article>`).join("")}</div>`;
}

/* ---- lexique (cartes) */
function vocab(el) {
  const V = m.vocab;
  el.innerHTML = `<div class="chips" id="vTh">${V.map((t, k) => `<button class="chip" type="button" data-t="${k}">${t.theme}</button>`).join("")}</div>
    <div class="row center exctl"><div class="chips" id="vSens"><button class="chip small" type="button" data-s="ab">${m.vocabSens[0]}</button><button class="chip small" type="button" data-s="ba">${m.vocabSens[1]}</button></div><button class="btn ghost" type="button" id="vList">Voir toute la liste</button></div>
    <div id="vBox"></div>`;
  const box = el.querySelector("#vBox");
  let deck = [], i = 0, su = 0, rv = [];
  const start = () => {
    el.querySelectorAll("#vTh .chip").forEach(b => b.setAttribute("aria-pressed", +b.dataset.t === s.vTheme));
    el.querySelectorAll("#vSens .chip").forEach(b => b.setAttribute("aria-pressed", b.dataset.s === s.vSens));
    deck = shuf(V[s.vTheme].mots).slice(0, 12); i = 0; su = 0; rv = []; card();
  };
  const card = () => {
    if (i >= deck.length) {
      box.innerHTML = `<div class="card flash"><div class="stat">${su} / ${deck.length}</div><p>termes connus.</p>${rv.length ? `<p>À revoir :</p>${OUT.T(m.vocabSens[0].split(" → "), rv)}` : "<p>Parfait, aucun terme à revoir.</p>"}<button class="btn" type="button" id="vAg">Nouvelle série de cartes</button></div>`;
      box.querySelector("#vAg").onclick = start; return;
    }
    const w = deck[i], [a, b] = s.vSens === "ab" ? w : [w[1], w[0]];
    box.innerHTML = `<div class="card flash"><p class="qhead"><span>${V[s.vTheme].theme}</span><span>Carte ${i + 1} / ${deck.length}</span></p><div class="front" style="font-size:${a.length > 40 ? "20px" : ""}">${a}</div><div class="back" hidden>${b}</div>
      <div class="row center"><button class="btn" type="button" id="vFlip">Retourner la carte</button></div>
      <div class="row center" id="vRate" hidden><button class="btn ghost" type="button" data-r="0">À revoir</button><button class="btn" type="button" data-r="1">Je savais</button></div></div>`;
    box.querySelector("#vFlip").onclick = () => { box.querySelector(".back").hidden = false; box.querySelector("#vFlip").parentElement.hidden = true; box.querySelector("#vRate").hidden = false; };
    box.querySelector("#vRate").onclick = e => { const r = e.target.dataset.r; if (r == null) return; if (r === "1") su++; else rv.push(w); i++; card(); };
  };
  el.querySelector("#vTh").onclick = e => { const b = e.target.closest(".chip"); if (b) { s.vTheme = +b.dataset.t; start(); } };
  el.querySelector("#vSens").onclick = e => { const b = e.target.closest(".chip"); if (b) { s.vSens = b.dataset.s; start(); } };
  el.querySelector("#vList").onclick = () => { box.innerHTML = `<div class="card">${OUT.T(m.vocabSens[0].split(" → "), V[s.vTheme].mots)}</div>`; };
  start();
}

route();
}
