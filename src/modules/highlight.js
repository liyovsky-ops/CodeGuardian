import Prism from 'prismjs';
// Disable Prism's built-in auto-highlight — we call highlightElement manually
window.Prism = window.Prism || {};
window.Prism.manual = true;

import 'prismjs/components/prism-python';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-c';
import 'prismjs/components/prism-markup-templating'; // required by php
import 'prismjs/components/prism-php';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-yaml';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-sql';
import 'prismjs/themes/prism-tomorrow.css';

export function highlightAll() {
  Prism.highlightAll();
}

export function highlightElement(el) {
  Prism.highlightElement(el);
}
