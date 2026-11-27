// SPDX-License-Identifier: AGPL-3.0-or-later
import '../assets/shauth.css';
import './preview.css';

export default {
  initialGlobals: { theme: 'system' },
  globalTypes: {
    theme: {
      description: 'Shauth color scheme',
      toolbar: {
        title: 'Theme',
        icon: 'circlehollow',
        dynamicTitle: true,
        items: [
          { value: 'system', title: 'System' },
          { value: 'light', title: 'Light' },
          { value: 'dark', title: 'Dark' },
        ],
      },
    },
  },
  parameters: {
    layout: 'fullscreen',
    options: { storySort: { order: ['Foundations', 'Components'] } },
    controls: { expanded: true },
  },
  decorators: [(Story, context) => {
    document.documentElement.dataset.theme = context.globals.theme || 'system';
    const wrapper = document.createElement('div');
    wrapper.className = 'component-preview';
    wrapper.innerHTML = `<nav class="component-links" aria-label="Shauth website"><strong>Shauth components</strong><a href="../" target="_top">Presentation</a><a href="../demo/" target="_top">Demo</a><a href="../docs/" target="_top">Docs</a><a href="../openapi.json" target="_top">OpenAPI</a></nav><main class="component-canvas"></main><p class="component-note">These component examples use synthetic data. They do not contact a live Shauth deployment.</p>`;
    const story = Story();
    const canvas = wrapper.querySelector('main');
    if (typeof story === 'string') canvas.innerHTML = story;
    else canvas.append(story);
    return wrapper;
  }],
};
