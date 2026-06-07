/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        arena: {
          root: '#0c1220',
          's1': '#111a2e',
          's2': '#162340',
          's3': '#1c2d4a',
          elevated: '#213555',
          border: '#304060',
          'border-dim': '#2a3f5f',
          title: '#f0f4ff',
          body: '#d0daf0',
          label: '#8a9bc0',
          muted: '#7088b0',
          red: '#ff6b7a',
          blue: '#5b9fff',
          green: '#34e08d',
          amber: '#ffcc55',
          interaction: '#a78bfa',
        },
      },
    },
  },
  plugins: [],
};
