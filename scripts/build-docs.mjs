// SPDX-License-Identifier: AGPL-3.0-or-later
// Render the repository documentation into the public Pages site.
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../website/package.json', import.meta.url));
const { Marked } = await import(require.resolve('marked'));

const root = fileURLToPath(new URL('../', import.meta.url));
const sourceDirectory = path.join(root, 'docs');
const outputDirectory = path.join(root, '.pages/docs');
const revision = process.env.GITHUB_SHA || 'ci/image-pin-freshness';
if (!/^[a-zA-Z0-9._/-]+$/.test(revision)) throw new Error('Invalid documentation source revision');
const repository = `https://github.com/e6qu/shauth/blob/${revision}/`;
const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const plain = value => String(value).replace(/<[^>]*>/g, '').replace(/&(?:amp|lt|gt|quot|#39);/g, entity => ({ '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'" })[entity]).replace(/\s+/g, ' ').trim();
const preferredOrder = ['integrating-apps', 'architecture', 'api', 'operations', 'gateway', 'development', 'demo'];
const names = (await readdir(sourceDirectory)).filter(name => name.endsWith('.md')).sort((a, b) => {
  const rank = name => { const index = preferredOrder.indexOf(name.slice(0, -3)); return index < 0 ? preferredOrder.length : index; };
  return rank(a) - rank(b) || a.localeCompare(b);
});
const documents = await Promise.all(names.map(async name => ({ name, slug: name.slice(0, -3), markdown: await readFile(path.join(sourceDirectory, name), 'utf8') })));
const knownDocuments = new Set(names);
const searchSections = [];

function rewriteLink(href, sourceName, image = false) {
  if (!href) return '';
  if (href === '../openapi.json') return '../openapi.json';
  if (/^(?:https?:|mailto:)/i.test(href) || href.startsWith('#')) return href;
  if (/^[a-z][a-z\d+.-]*:/i.test(href) || href.startsWith('//')) throw new Error(`Unsupported documentation link in ${sourceName}: ${href}`);
  const resolved = new URL(href, `https://repository.invalid/docs/${sourceName}`);
  const pathname = decodeURIComponent(resolved.pathname).replace(/^\//, '');
  if (pathname.startsWith('docs/') && knownDocuments.has(pathname.slice(5))) return `${pathname.slice(5, -3)}.html${resolved.search}${resolved.hash}`;
  return `${image ? 'https://raw.githubusercontent.com/e6qu/shauth/main/' : repository}${pathname}${resolved.search}${resolved.hash}`;
}

function renderDocument(document) {
  const toc = [];
  const usedIds = new Map();
  const blocks = [];
  let currentSection;
  const markdown = new Marked({ gfm: true });
  markdown.use({ renderer: {
    heading({ tokens, depth }) {
      const inline = this.parser.parseInline(tokens);
      const text = plain(inline);
      const base = text.toLowerCase().replace(/[^\p{L}\p{N}_\s-]/gu, '').replace(/\s/g, '-') || 'section';
      const count = usedIds.get(base) || 0;
      usedIds.set(base, count + 1);
      const id = count ? `${base}-${count}` : base;
      if (depth === 1) document.title = text;
      if (depth >= 2 && depth <= 3) toc.push({ id, text, depth });
      currentSection = { title: text, pageTitle: document.title, url: `${document.slug}.html#${id}`, text: '' };
      blocks.push(currentSection);
      return `<h${depth} id="${escape(id)}">${inline}<a class="docs-heading-link" href="#${escape(id)}" aria-label="Link to ${escape(text)}">#</a></h${depth}>\n`;
    },
    paragraph({ tokens }) {
      const inline = this.parser.parseInline(tokens);
      const text = plain(inline);
      if (!document.description) document.description = text;
      if (currentSection) currentSection.text += `${text} `;
      return `<p>${inline}</p>\n`;
    },
    link({ href, title, tokens }) {
      return `<a href="${escape(rewriteLink(href, document.name))}"${title ? ` title="${escape(title)}"` : ''}>${this.parser.parseInline(tokens)}</a>`;
    },
    image({ href, title, text }) {
      return `<img src="${escape(rewriteLink(href, document.name, true))}" alt="${escape(text)}"${title ? ` title="${escape(title)}"` : ''} loading="lazy">`;
    },
    html({ text }) {
      return text.replace(/<!--[\s\S]*?-->/g, '').trim() ? escape(text) : '';
    },
  } });
  document.html = markdown.parse(document.markdown)
    .replace(/<table>/g, '<div class="docs-table" tabindex="0" role="region" aria-label="Documentation table"><table>')
    .replace(/<\/table>/g, '</table></div>')
    .replace(/<pre>/g, '<pre tabindex="0" aria-label="Code example">');
  if (!document.title) throw new Error(`Documentation must have a title: ${document.name}`);
  document.toc = toc;
  // Index complete text as well as prose, so endpoint names in tables and code
  // remain searchable without copying or maintaining a second documentation set.
  const body = plain(document.html);
  searchSections.push({ title: document.title, pageTitle: document.title, url: `${document.slug}.html`, text: body });
  searchSections.push(...blocks.filter(block => block.text.trim()).map(block => ({ ...block, text: block.text.trim() })));
}
for (const document of documents) renderDocument(document);

function pageShell({ title, description, active, content, toc = [], source }) {
  const navigation = documents.map(document => `<a href="${escape(document.slug)}.html"${document.slug === active ? ' aria-current="page"' : ''}>${escape(document.title)}</a>`).join('');
  return `<!doctype html>
<html lang="en" data-theme="system">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta name="description" content="${escape(description)}">
  <title>${escape(title)} · Shauth documentation</title>
  <link rel="icon" href="../assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="../assets/shauth.css">
  <link rel="stylesheet" href="../docs.css">
  <script src="../assets/theme.js"></script>
  <script src="../docs-search.js" type="module"></script>
</head>
<body class="docs-site">
  <a class="skip-link" href="#main-content">Skip to documentation</a>
  <header class="site-header"><div class="header-inner">
    <a class="brand" href="../"><img src="../assets/favicon.svg" alt="" width="32" height="32">Shauth</a>
    <nav class="nav" aria-label="Site navigation"><a href="../demo/">Demo</a><a href="../storybook/">Storybook</a><a href="./" aria-current="page">Docs</a><a href="../openapi.json">OpenAPI</a><button class="theme-button" id="theme-toggle" type="button" hidden>◐ Theme</button></nav>
  </div></header>
  <div class="docs-layout">
    <aside class="docs-sidebar" aria-label="Documentation navigation">
      <section class="docs-search" hidden>
        <form role="search"><label for="docs-search">Search documentation</label><input type="search" id="docs-search" placeholder="Sessions, logout, API…" autocomplete="off" aria-controls="docs-search-results" aria-describedby="docs-search-status"></form>
        <p id="docs-search-status" class="docs-search-status" role="status"></p>
        <ul id="docs-search-results" class="docs-search-results" hidden></ul>
      </section>
      <details class="docs-navigation" open><summary>Documentation</summary><nav aria-label="Documentation pages"><a href="./"${active === 'index' ? ' aria-current="page"' : ''}>Overview</a>${navigation}<a href="../openapi.json">OpenAPI specification</a></nav></details>
      <a class="docs-repository" href="https://github.com/e6qu/shauth">Source repository</a>
    </aside>
    <main id="main-content" class="docs-content">
      <div class="docs-article-topline"><p class="eyebrow">Shauth documentation</p>${source ? `<a href="${repository}docs/${escape(source)}">View Markdown source</a>` : ''}</div>
      ${toc.length ? `<details class="docs-contents"><summary>On this page</summary><nav aria-label="On this page"><ul>${toc.map(item => `<li class="docs-depth-${item.depth}"><a href="#${escape(item.id)}">${escape(item.text)}</a></li>`).join('')}</ul></nav></details>` : ''}
      <article class="docs-prose">${content}</article>
      <footer class="docs-article-footer"><a href="../demo/">Try the interactive demo</a><a href="../storybook/">Explore components</a><a href="../openapi.json">Download OpenAPI JSON</a></footer>
    </main>
  </div>
</body>
</html>
`;
}

await mkdir(outputDirectory, { recursive: true });
const overview = `<h1>Build on a shared identity.</h1>
<p class="docs-introduction">Connect applications with OpenID Connect, manage access, and operate Shauth with confidence. These pages are built directly from the project’s maintained documentation.</p>
<div class="docs-start"><h2>Start with an application</h2><p>The integration guide covers client registration, sign-in, global logout, and the browser checks that verify the full journey.</p><a class="button" href="integrating-apps.html">Connect an application</a><a href="architecture.html">Understand the architecture</a></div>
<section class="docs-overview-grid" aria-label="Documentation guides">${documents.map(document => `<a class="docs-guide" href="${escape(document.slug)}.html"><h2>${escape(document.title)}</h2><p>${escape((document.description || '').slice(0, 190))}${(document.description || '').length > 190 ? '…' : ''}</p></a>`).join('')}</section>
<section class="docs-api-link"><h2>A contract for your tools</h2><p>Use the machine-readable API specification alongside the human-readable administration API guide.</p><a class="button button-secondary" href="../openapi.json">Open the API specification</a></section>`;
await writeFile(path.join(outputDirectory, 'index.html'), pageShell({ title: 'Overview', description: 'Shauth documentation: integration, identity architecture, API reference, operations, and development.', active: 'index', content: overview }));
for (const document of documents) {
  await writeFile(path.join(outputDirectory, `${document.slug}.html`), pageShell({ title: document.title, description: document.description || document.title, active: document.slug, content: document.html, toc: document.toc, source: document.name }));
}
await writeFile(path.join(outputDirectory, 'search.json'), `${JSON.stringify({ sections: searchSections })}\n`);
console.log(`Documentation: rendered ${documents.length} source pages and ${searchSections.length} searchable sections`);
