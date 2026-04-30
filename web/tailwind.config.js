/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,ts}'],
  theme: {
    extend: {
      colors: {
        vault42: {
          bg: '#0a0a0f',
          surface: '#12121a',
          border: '#1e1e2e',
          primary: '#6366f1',
          accent: '#818cf8',
          text: '#e2e8f0',
          muted: '#64748b',
          success: '#22c55e',
          error: '#ef4444',
        },
      },
    },
  },
  plugins: [],
}
