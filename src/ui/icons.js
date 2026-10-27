const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';

export function icon(name, size = 17, strokeWidth = 1.65, className = '') {
  if (!/^[a-z0-9-]+$/.test(name)) throw new Error('Invalid icon name.');
  const safeSize = Number(size) || 17;
  const safeStroke = Number(strokeWidth) || 1.65;
  const safeClass = String(className).replace(/[^a-zA-Z0-9 _-]/g, '');
  return `<svg width="${safeSize}" height="${safeSize}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${safeStroke}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${safeClass ? ` class="${safeClass}"` : ''}><use href="/icons.svg#${name}"></use></svg>`;
}

export function setIcon(element, name) {
  if (!element || !/^[a-z0-9-]+$/.test(name)) return;
  element.setAttribute('viewBox', '0 0 24 24');
  element.setAttribute('fill', 'none');
  element.setAttribute('stroke', 'currentColor');
  element.setAttribute('stroke-width', element.dataset.stroke || '1.65');
  element.setAttribute('stroke-linecap', 'round');
  element.setAttribute('stroke-linejoin', 'round');
  element.setAttribute('aria-hidden', 'true');
  let use = element.querySelector('use');
  if (!use) { use = element.ownerDocument.createElementNS(SVG_NAMESPACE, 'use'); element.append(use); }
  use.setAttribute('href', `/icons.svg#${name}`);
  element.dataset.icon = name;
}

export function hydrateIcons(root) {
  for (const element of root.querySelectorAll('svg[data-icon]')) setIcon(element, element.dataset.icon);
}
