/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:      "#060911",
          panel:   "#0c1220",
          border:  "#1a2744",
          accent:  "#00d4ff",
          red:     "#ff3b5c",
          yellow:  "#f5c518",
          green:   "#00ff9d",
          purple:  "#9d4edd",
          dim:     "#8899bb",
        }
      },
      fontFamily: {
        mono:    ["'JetBrains Mono'", "monospace"],
        display: ["'Rajdhani'", "sans-serif"],
        body:    ["'IBM Plex Sans'", "sans-serif"],
      },
      animation: {
        "scan-line": "scanLine 3s linear infinite",
        "pulse-red": "pulseRed 2s ease-in-out infinite",
        "blink":     "blink 1s step-end infinite",
        "glitch":    "glitch 0.4s ease infinite alternate",
        "fade-in":   "fadeIn 0.4s ease-out",
        "slide-up":  "slideUp 0.35s ease-out",
      },
      keyframes: {
        scanLine: {
          "0%":   { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        pulseRed: {
          "0%, 100%": { boxShadow: "0 0 0 0 rgba(255,59,92,0)" },
          "50%":       { boxShadow: "0 0 12px 4px rgba(255,59,92,0.4)" },
        },
        blink: {
          "0%, 100%": { opacity: 1 },
          "50%":       { opacity: 0 },
        },
        fadeIn: {
          from: { opacity: 0, transform: "translateY(8px)" },
          to:   { opacity: 1, transform: "translateY(0)" },
        },
        slideUp: {
          from: { opacity: 0, transform: "translateY(20px)" },
          to:   { opacity: 1, transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
