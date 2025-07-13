const postcss = require("postcss");
const tailwindcss = require("tailwindcss");

// Call tailwindcss() as a function here
postcss([tailwindcss()]) // <--- CHANGE THIS LINE
  .process(require("fs").readFileSync("css/styles.css", "utf8"), {
    from: "css/styles.css",
    to: "css/output.css",
  })
  .then(result => require("fs").writeFileSync("css/output.css", result.css));