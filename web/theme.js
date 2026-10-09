// Applique le thème mémorisé avant le premier affichage (fichier séparé : la CSP interdit les scripts en ligne).
try { const t = localStorage.getItem("nw-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* ignore */ }
