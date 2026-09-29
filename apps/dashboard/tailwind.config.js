/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0a0d14',
          card: '#121722',
          border: '#1e2638',
          accent: '#3b82f6',
          cyan: '#06b6d4',
          emerald: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
          text: '#f3f4f6',
          muted: '#9ca3af'
        }
      }
    },
  },
  plugins: [],
}
