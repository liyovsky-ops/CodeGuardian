import matrixData from '../content/matrix.yaml';
import { getLang } from '../i18n/index.js';

export function getMatrix() {
  const lang = getLang();
  return matrixData.matrix.map(row => lang === 'en' ? (row.cells_en || row.cells) : row.cells);
}

// Backward compat static export (Polish, used before i18n)
export const MATRIX = matrixData.matrix.map(row => row.cells);
