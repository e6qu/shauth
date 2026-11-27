// SPDX-License-Identifier: AGPL-3.0-or-later
export default {
  stories: ['../stories/**/*.stories.js'],
  framework: { name: '@storybook/html-vite', options: {} },
  core: { disableTelemetry: true },
  viteFinal: async config => ({ ...config, base: './' }),
};
