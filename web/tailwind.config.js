/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:      "#0a0e1a",
          surface: "#111827",
          card:    "#1a2236",
          border:  "#1e2d45",
          accent:  "#00d4ff",
          green:   "#00ff88",
          red:     "#ff3b3b",
          orange:  "#ff8c00",
          yellow:  "#ffd700",
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      }
    },
  },
  plugins: [],
}