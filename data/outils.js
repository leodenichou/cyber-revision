/* Petits outils partagés par les fichiers de matières (tirages au hasard, tableaux). */
const OUT = (() => {
  const R = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
  const pick = a => a[R(0, a.length - 1)];
  const shuf = a => { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = R(0, i); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  const T = (head, rows) => `<div class="scroll"><table><thead><tr>${head.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(v => `<td>${v}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const fr = (x, d = 1) => Number(x).toLocaleString("fr-FR", { minimumFractionDigits: d, maximumFractionDigits: d });
  const box = (titre, html, cls = "def") => `<div class="box ${cls}"><b>${titre}</b>${html}</div>`;
  return { R, pick, shuf, T, fr, box };
})();



/* Exemples annotés en couleur pour la méthodologie.
   OUT.mk(n, texte) colore un passage (n de 1 à 6) ;
   OUT.exemple(titre, [[n, "nom de la couleur"], …], html) construit le bloc avec sa légende. */
OUT.mk = (n, t) => `<span class="mk mk${n}">${t}</span>`;
OUT.exemple = (titre, legende, html) => `<div class="exemple"><p class="ex-titre">${titre}</p><div class="legende">${legende.map(([n, l]) => `<span class="mk mk${n}">${l}</span>`).join("")}</div><div class="ex-texte">${html}</div></div>`;
