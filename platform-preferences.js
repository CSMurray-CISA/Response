"use strict";

(() => {
  const THEME_KEY = "advisoryLensTheme";
  const FONT_KEY = "advisoryLensFontSize";
  const validThemes = new Set(["dark", "light"]);
  const validFonts = new Set(["normal", "large"]);

  function currentPreferences() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    const savedFont = localStorage.getItem(FONT_KEY);
    return {
      theme: validThemes.has(savedTheme) ? savedTheme : "dark",
      fontSize: validFonts.has(savedFont) ? savedFont : "normal"
    };
  }

  function applyPreferences(preferences) {
    const theme = validThemes.has(preferences?.theme) ? preferences.theme : "dark";
    const fontSize = validFonts.has(preferences?.fontSize) ? preferences.fontSize : "normal";
    document.documentElement.dataset.platformTheme = theme;
    document.documentElement.dataset.platformFont = fontSize;
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem("theme", theme);

    if (document.body) {
      document.body.classList.toggle("dark", theme === "dark");
    }
  }

  function retirePageSpecificControls() {
    document.querySelectorAll(".mode").forEach(element => {
      element.hidden = true;
      element.setAttribute("aria-hidden", "true");
    });
    const legacyTheme = document.getElementById("theme");
    if (legacyTheme) {
      const wrapper = legacyTheme.closest("label");
      if (wrapper) wrapper.hidden = true;
    }
  }

  applyPreferences(currentPreferences());

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      applyPreferences(currentPreferences());
      retirePageSpecificControls();
    });
  } else {
    applyPreferences(currentPreferences());
    retirePageSpecificControls();
  }

  window.addEventListener("message", event => {
    if (event.origin !== window.location.origin) return;
    if (event.data?.type !== "advisory-lens-preferences") return;
    applyPreferences(event.data);
    retirePageSpecificControls();
  });

  window.addEventListener("storage", event => {
    if (event.key === THEME_KEY || event.key === FONT_KEY) {
      applyPreferences(currentPreferences());
    }
  });

  window.advisoryLensPreferences = {
    apply: applyPreferences,
    read: currentPreferences,
    keys: { theme: THEME_KEY, fontSize: FONT_KEY }
  };
})();
