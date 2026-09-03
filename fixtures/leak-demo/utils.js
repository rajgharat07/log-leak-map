// Leftover local debug — ships API_KEY into stdout on every boot.
const API_KEY = process.env.API_KEY;

function boot() {
  console.log("DEBUG token", process.env.API_KEY);
}

module.exports = { boot, API_KEY };
