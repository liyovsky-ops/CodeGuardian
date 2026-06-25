import { $, $$ } from './dom.js';
import { highlightCard } from './renderer.js';
import { SCROLL_ACTIVE_OFFSET, BACK_TO_TOP_THRESHOLD } from '../config.js';
import { openDeepDivePage } from './deepdive-renderer.js';
import sqliData from '../content/deepdives/sqli.yaml';
import nosqliData from '../content/deepdives/nosqli.yaml';
import cmdiData from '../content/deepdives/cmdi.yaml';
import ldapiData from '../content/deepdives/ldapi.yaml';
import xpathiData from '../content/deepdives/xpathi.yaml';
import sstiData from '../content/deepdives/ssti.yaml';
import logiData from '../content/deepdives/logi.yaml';
import crlfiData from '../content/deepdives/crlfi.yaml';
import hhiData from '../content/deepdives/hhi.yaml';
import emailiData from '../content/deepdives/emaili.yaml';
import csviData from '../content/deepdives/csvi.yaml';

const DEEPDIVE_HANDLERS = {
  '1.1': () => openDeepDivePage(sqliData),
  '1.2': () => openDeepDivePage(nosqliData),
  '1.3': () => openDeepDivePage(cmdiData),
  '1.4': () => openDeepDivePage(ldapiData),
  '1.5': () => openDeepDivePage(xpathiData),
  '1.6': () => openDeepDivePage(sstiData),
  '1.7': () => openDeepDivePage(logiData),
  '1.8': () => openDeepDivePage(crlfiData),
  '1.9': () => openDeepDivePage(hhiData),
  '1.10': () => openDeepDivePage(emailiData),
  '1.11': () => openDeepDivePage(csviData),
};

function wireCollapsible() {
  $$('.threat-head').forEach((head) => {
    const toggle = () => {
      const card = head.closest('.threat');
      const open = card.classList.toggle('open');
      head.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) highlightCard(card);
    };
    head.addEventListener('click', toggle);
    head.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggle();
      }
    });
  });
}

function wireTabs() {
  $$('.code-area').forEach((area) => {
    $$('.tab', area).forEach((tab) => {
      tab.addEventListener('click', (e) => {
        e.stopPropagation();
        const which = tab.dataset.tab;
        $$('.tab', area).forEach((t) => t.classList.toggle('active', t === tab));
        $$('.tab-panel', area).forEach((p) =>
          p.classList.toggle('active', p.dataset.panel === which)
        );
      });
    });
  });
}

function wireMobileMenu() {
  const btn = $('#hamburger');
  const sidebar = $('#sidebar');
  const overlay = $('#overlay');
  const close = () => {
    sidebar.classList.remove('open');
    overlay.classList.remove('show');
  };
  btn.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    overlay.classList.toggle('show');
  });
  overlay.addEventListener('click', close);
  $$('.side-link').forEach((l) => l.addEventListener('click', close));
}

function updateActiveSection(categories) {
  const links = $$('.side-link');
  let current = '';
  categories.forEach((c) => {
    const sec = $('#cat-' + c.id);
    if (sec && sec.getBoundingClientRect().top <= SCROLL_ACTIVE_OFFSET) current = c.id;
  });
  links.forEach((l) => l.classList.toggle('active', l.dataset.cat === current));
}

function wireScroll(categories) {
  const bar = $('#progress-bar');
  const top = $('#back-to-top');
  const onScroll = () => {
    const h = document.documentElement;
    const scrolled = h.scrollTop;
    const height = h.scrollHeight - h.clientHeight;
    const pct = height > 0 ? (scrolled / height) * 100 : 0;
    bar.style.width = pct + '%';
    top.classList.toggle('show', scrolled > BACK_TO_TOP_THRESHOLD);
    updateActiveSection(categories);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  top.addEventListener('click', () =>
    window.scrollTo({ top: 0, behavior: 'smooth' })
  );
  onScroll();
}

function openAnchor() {
  const id = location.hash.replace('#', '');
  const card = id && document.getElementById(id);
  if (card && card.classList.contains('threat') && !card.classList.contains('open')) {
    card.classList.add('open');
    card.querySelector('.threat-head').setAttribute('aria-expanded', 'true');
    highlightCard(card);
  }
}

function wireDeepDive() {
  $$('.deepdive-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const handler = DEEPDIVE_HANDLERS[btn.dataset.threatId];
      if (handler) handler();
    });
  });
}

export function wireDynamicInteractions() {
  wireCollapsible();
  wireTabs();
  wireDeepDive();
  // Re-attach side-link close handlers (sidebar nav is rebuilt)
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay');
  if (sidebar && overlay) {
    const close = () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('show');
    };
    document.querySelectorAll('.side-link').forEach((l) => l.addEventListener('click', close));
  }
}

export function initInteractions(categories) {
  wireMobileMenu();
  wireScroll(categories);

  window.addEventListener('hashchange', openAnchor);
  openAnchor();
}
