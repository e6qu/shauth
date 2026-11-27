// SPDX-License-Identifier: AGPL-3.0-or-later
const section = document.querySelector('.docs-search');
const input = document.querySelector('#docs-search');
const results = document.querySelector('#docs-search-results');
const status = document.querySelector('#docs-search-status');
document.querySelector('#theme-toggle').hidden = false;
section.hidden = false;
section.querySelector('form').addEventListener('submit', event => event.preventDefault());
const normalize = value => value.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
let index;
let loadFailure = false;

function renderResults() {
  const query = input.value.trim();
  results.replaceChildren();
  results.hidden = true;
  if (!query) { status.textContent = ''; return; }
  if (loadFailure) { status.textContent = 'Search could not load. Use the documentation navigation to open a guide.'; return; }
  if (!index) { status.textContent = 'Loading documentation search…'; return; }
  const words = normalize(query).split(/\s+/).filter(Boolean);
  const ranked = index.map(entry => {
    const title = normalize(`${entry.pageTitle} ${entry.title}`);
    const text = normalize(entry.text);
    return { entry, score: words.every(word => `${title} ${text}`.includes(word)) ? words.reduce((score, word) => score + (title.includes(word) ? 4 : 1), 0) : 0 };
  }).filter(result => result.score > 0).sort((a, b) => b.score - a.score);
  const matches = ranked.slice(0, 8);
  status.textContent = matches.length ? `${ranked.length} matching section${ranked.length === 1 ? '' : 's'}${ranked.length > 8 ? '; showing the first 8' : ''}.` : 'No matching sections. Try an endpoint name or a broader term.';
  for (const { entry } of matches) {
    const item = document.createElement('li');
    const link = document.createElement('a');
    link.href = entry.url;
    const title = document.createElement('strong');
    title.textContent = entry.title === entry.pageTitle ? entry.title : `${entry.pageTitle} · ${entry.title}`;
    const excerpt = document.createElement('span');
    const matchedAt = normalize(entry.text).indexOf(words[0]);
    const start = Math.max(0, matchedAt - 45);
    excerpt.textContent = `${start ? '…' : ''}${entry.text.slice(start, start + 150)}${entry.text.length > start + 150 ? '…' : ''}`;
    link.append(title, excerpt);
    item.append(link);
    results.append(item);
  }
  results.hidden = matches.length === 0;
}
input.addEventListener('input', renderResults);
input.addEventListener('keydown', event => {
  if (event.key === 'Escape') { input.value = ''; renderResults(); }
  if (event.key === 'ArrowDown' && !results.hidden) { event.preventDefault(); results.querySelector('a')?.focus(); }
});
results.addEventListener('keydown', event => {
  const links = [...results.querySelectorAll('a')];
  const current = links.indexOf(document.activeElement);
  if (event.key === 'Escape') { input.focus(); return; }
  if (event.key === 'ArrowDown') { event.preventDefault(); links[Math.min(current + 1, links.length - 1)]?.focus(); }
  if (event.key === 'ArrowUp') { event.preventDefault(); if (current <= 0) input.focus(); else links[current - 1].focus(); }
});
try {
  const response = await fetch(new URL('docs/search.json', new URL('.', import.meta.url)), { signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  if (!Array.isArray(data.sections)) throw new Error('Search index is invalid');
  index = data.sections;
} catch (error) {
  loadFailure = true;
  console.error('Documentation search could not load:', error);
}
renderResults();
