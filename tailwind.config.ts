/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./auth/**/*.{hbs,js}",
        // Add additional patterns here if needed
        // "./other-folder/**/*.{hbs,js}"
    ],
    theme: {
      extend: {},
    },
    plugins: [
      require('@tailwindcss/typography')
    ],
  }