// =====================================================
// EasyTube AdBlock - AdGuard + Banery + Live Fix
// =====================================================

(function() {
    // Sprawdź czy blokowanie reklam jest włączone
    const adblockEnabled = window.__easytube_adblock_enabled !== false;
    
    if (!adblockEnabled) {
        // Jeśli wyłączone, usuń wszystkie elementy blokujące
        const elements = document.querySelectorAll('#block-youtube-ads-logo, #block-youtube-ads-style, #easytube-extra-adblock, #easytube-live-fix, #easytube-sponsored-blocks, #easytube-login-fix');
        elements.forEach(el => el.remove());
        return;
    }
    
    // =====================================================
    // POMOCNICZA FUNKCJA DO BEZPIECZNEGO DODAWANIA STYLI
    // =====================================================
    const safeAppendStyle = (id, css) => {
        try {
            if (!document || !document.head) {
                // Jeśli head nie istnieje, spróbuj ponownie za chwilę
                setTimeout(() => safeAppendStyle(id, css), 50);
                return;
            }
            if (document.getElementById(id)) {
                return;
            }
            const style = document.createElement('style');
            style.id = id;
            style.textContent = css;
            document.head.appendChild(style);
        } catch(e) {
            // Ignoruj błędy
        }
    };
    
    // =====================================================
    // 1. NAPRAWA DLA TRANSMISJI NA ŻYWO (LIVE)
    // =====================================================
    const fixLiveStream = () => {
        try {
            // Usuń WSZYSTKIE elementy związane z błędami
            const removeSelectors = [
                '.ytp-unsupported-browser-overlay',
                '.ytp-unsupported-browser',
                '.ytp-error-message',
                '.ytp-error-content',
                '.ytp-error',
                '.ytp-error-screen',
                '.ytp-error .ytp-error-content',
                '.ytp-error .ytp-error-text',
                '.ytp-error .ytp-error-message',
                '.ytp-error-overlay',
                '.ytp-error-overlay-container',
                '.ytp-error-overlay-content',
                '.ytp-playback-error',
                '.ytp-playback-error-message',
                '.ytp-playback-error-content',
                '[class*="unsupported"]:not(.ytp-chrome-controls)',
                '[class*="error-screen"]:not(.ytp-chrome-controls)',
                '[class*="error-message"]:not(.ytp-chrome-controls)'
            ];
            
            removeSelectors.forEach(selector => {
                try {
                    document.querySelectorAll(selector).forEach(el => {
                        if (el && el.parentNode) {
                            el.style.display = 'none';
                            el.style.visibility = 'hidden';
                            el.style.opacity = '0';
                            el.style.height = '0';
                            el.style.minHeight = '0';
                            el.style.maxHeight = '0';
                            el.style.overflow = 'hidden';
                            el.style.pointerEvents = 'none';
                            try { el.remove(); } catch(e) {}
                        }
                    });
                } catch(e) {}
            });
            
            // Usuń elementy z tekstem o błędzie
            try {
                document.querySelectorAll('*').forEach(el => {
                    if (el && el.textContent && (
                        el.textContent.includes('Nie możesz odtworzyć') ||
                        el.textContent.includes('Cannot play') ||
                        el.textContent.includes('browser') ||
                        el.textContent.includes('unsupported') ||
                        el.textContent.includes('not supported') ||
                        el.textContent.includes('w swojej przeglądarce') ||
                        el.textContent.includes('przeglądarka nie jest obsługiwana') ||
                        el.textContent.includes('This browser is not supported')
                    )) {
                        if (!el.closest('.ytp-chrome-controls') && 
                            !el.closest('.ytp-progress-bar') &&
                            !el.closest('.ytp-volume-panel') &&
                            !el.closest('.ytp-fullscreen-button')) {
                            el.style.display = 'none';
                            el.style.visibility = 'hidden';
                            el.style.opacity = '0';
                            el.style.height = '0';
                            try { el.remove(); } catch(e) {}
                        }
                    }
                });
            } catch(e) {}
            
            // Dodaj styl dla live
            safeAppendStyle('easytube-live-fix', `
                .ytp-unsupported-browser-overlay,
                .ytp-unsupported-browser,
                .ytp-error-message,
                .ytp-error-content,
                .ytp-error,
                .ytp-error-screen,
                .ytp-error-overlay,
                .ytp-error-overlay-container,
                .ytp-error-overlay-content,
                .ytp-playback-error,
                [class*="unsupported"]:not(.ytp-chrome-controls),
                [class*="error-screen"]:not(.ytp-chrome-controls),
                [class*="error-message"]:not(.ytp-chrome-controls) {
                    display: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                    height: 0 !important;
                    min-height: 0 !important;
                    max-height: 0 !important;
                    overflow: hidden !important;
                    pointer-events: none !important;
                    position: absolute !important;
                    top: -9999px !important;
                    left: -9999px !important;
                    width: 0 !important;
                    max-width: 0 !important;
                    padding: 0 !important;
                    margin: 0 !important;
                    border: 0 !important;
                }
                #movie_player {
                    display: block !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                    background: #000 !important;
                }
                #movie_player video {
                    display: block !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                    width: 100% !important;
                    height: 100% !important;
                }
                .html5-video-player {
                    display: block !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                    background: #000 !important;
                }
                .ytp-error-content-renderer {
                    display: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                }
            `);
            
            // Spróbuj odtworzyć wideo
            try {
                const video = document.querySelector('video');
                if (video) {
                    video.removeAttribute('disablepictureinpicture');
                    video.removeAttribute('disableremoteplayback');
                    if (video.paused && video.src) {
                        video.play().catch(() => {});
                    }
                    if (video.src && video.src.includes('live')) {
                        video.setAttribute('crossorigin', 'anonymous');
                    }
                    video.removeAttribute('poster');
                }
            } catch(e) {}
            
        } catch(e) {
            // Ignoruj błędy
        }
    };
    
    // =====================================================
    // 2. ADGUARD - BLOKOWANIE REKLAM W FILMACH
    // =====================================================
    const runAdGuard = () => {
        try {
            if (!document || !document.head) {
                setTimeout(runAdGuard, 100);
                return;
            }
            
            const locales = {
                en: {
                    logo: "with&nbsp;AdGuard",
                    alreadyExecuted: "The shortcut has already been executed.",
                    wrongDomain: "This shortcut is supposed to be launched only on YouTube.",
                    success: "YouTube is now ad-free!"
                },
                pl: {
                    logo: "z&nbsp;AdGuard",
                    alreadyExecuted: "Skrypt został już wykonany.",
                    wrongDomain: "Ten skrypt działa tylko na YouTube.",
                    success: "YouTube jest teraz bez reklam!"
                }
            };
            
            const getMessage = (key) => {
                try {
                    const lang = navigator.language ? navigator.language.split('-')[0] : 'en';
                    const locale = locales[lang] || locales.en;
                    return locale[key] || locales.en[key];
                } catch(e) {
                    return locales.en[key];
                }
            };
            
            if (document.getElementById("block-youtube-ads-logo")) {
                return;
            }
            
            const hostname = window.location ? window.location.hostname : '';
            if (hostname !== "www.youtube.com" && hostname !== "m.youtube.com" && hostname !== "music.youtube.com") {
                return;
            }
            
            const pageScript = () => {
                const LOGO_ID = "block-youtube-ads-logo";
                const hiddenCSS = {
                    "www.youtube.com": [
                        "#feed-pyv-container",
                        "#merch-shelf",
                        "#pla-shelf",
                        "#promo-info",
                        "#promo-list",
                        "#promotion-shelf",
                        "#search-pva",
                        "#shelf-pyv-container",
                        "#video-masthead",
                        "#watch-branded-actions",
                        ".companion-ad-container",
                        ".promoted-videos",
                        ".ytd-carousel-ad-renderer",
                        ".ytd-compact-promoted-video-renderer",
                        ".ytd-companion-slot-renderer",
                        ".ytd-merch-shelf-renderer",
                        ".ytd-promoted-video-renderer",
                        ".ytd-search-pyv-renderer",
                        ".ytd-video-masthead-ad-v3-renderer",
                        ".ytp-ad-image-overlay",
                        ".ytp-ad-overlay-container",
                        "ytd-banner-promo-renderer",
                        "ytd-display-ad-renderer",
                        "ytd-promoted-sparkles-web-renderer",
                        "ytd-promoted-video-renderer",
                        "ytd-search-pyv-renderer"
                    ]
                };
                
                const hideElements = (hostname) => {
                    const selectors = hiddenCSS[hostname];
                    if (!selectors || !document.head) return;
                    try {
                        const rule = `${selectors.join(", ")} { display: none!important; }`;
                        const style = document.createElement("style");
                        style.id = 'block-youtube-ads-style';
                        style.textContent = rule;
                        document.head.appendChild(style);
                    } catch(e) {}
                };
                
                const autoSkipAds = () => {
                    try {
                        if (document.querySelector(".ad-showing")) {
                            const video = document.querySelector("video");
                            if (video && video.duration) {
                                video.currentTime = video.duration;
                                setTimeout(() => {
                                    const skipBtn = document.querySelector("button.ytp-ad-skip-button");
                                    if (skipBtn) skipBtn.click();
                                }, 100);
                            }
                        }
                    } catch(e) {}
                };
                
                const addAdGuardLogo = () => {
                    try {
                        if (document.getElementById(LOGO_ID) || !document.head) return;
                        const logo = document.createElement("span");
                        logo.innerHTML = "__logo_text__";
                        logo.setAttribute("id", LOGO_ID);
                        const code = document.getElementById("country-code");
                        if (code) {
                            code.innerHTML = "";
                            code.appendChild(logo);
                        }
                    } catch(e) {}
                };
                
                try {
                    hideElements(window.location.hostname);
                    addAdGuardLogo();
                    autoSkipAds();
                    
                    // Obserwuj zmiany
                    const observer = new MutationObserver(() => {
                        addAdGuardLogo();
                        autoSkipAds();
                        fixLiveStream();
                    });
                    if (document.documentElement) {
                        observer.observe(document.documentElement, {
                            childList: true,
                            subtree: true
                        });
                    }
                } catch(e) {}
            };
            
            try {
                const script = document.createElement("script");
                const scriptText = pageScript.toString().replace("__logo_text__", getMessage("logo"));
                script.innerHTML = `(${scriptText})();`;
                document.head.appendChild(script);
                document.head.removeChild(script);
            } catch(e) {}
            
        } catch(e) {
            // Ignoruj błędy
        }
    };
    
    // =====================================================
    // 3. BLOKOWANIE BANERÓW SPONSOROWANYCH
    // =====================================================
    const blockSponsoredBanners = () => {
        try {
            if (!document || !document.head) {
                setTimeout(blockSponsoredBanners, 100);
                return;
            }
            
            safeAppendStyle('easytube-sponsored-blocks', `
                ytd-rich-item-renderer:has(ytd-display-ad-renderer),
                ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
                ytd-rich-item-renderer:has(ytd-promoted-video-renderer),
                ytd-rich-item-renderer:has([class*="sponsored"]),
                ytd-rich-item-renderer:has([class*="ad-badge"]),
                ytd-rich-item-renderer:has([class*="promoted"]),
                ytd-banner-renderer,
                ytd-banner-promo-renderer,
                ytd-merch-shelf-renderer,
                ytd-carousel-ad-renderer,
                ytd-video-masthead-ad-v3-renderer,
                #contents > ytd-rich-item-renderer > ytd-display-ad-renderer,
                [class*="ad-container"],
                [class*="ad-badge"],
                [class*="sponsored"],
                [class*="promoted"],
                ytd-search-pyv-renderer,
                ytd-promoted-sparkles-web-renderer,
                ytd-promoted-sparkles-text-search-renderer {
                    display: none !important;
                    min-height: 0 !important;
                    max-height: 0 !important;
                    height: 0 !important;
                    overflow: hidden !important;
                    padding: 0 !important;
                    margin: 0 !important;
                }
            `);
            
            const removeSponsoredElements = () => {
                try {
                    document.querySelectorAll('ytd-rich-item-renderer').forEach(el => {
                        if (el.querySelector('ytd-display-ad-renderer, ytd-ad-slot-renderer, ytd-promoted-video-renderer')) {
                            el.style.display = 'none';
                            el.style.height = '0';
                            el.style.overflow = 'hidden';
                        }
                    });
                    
                    const adSelectors = [
                        'ytd-display-ad-renderer', 
                        'ytd-ad-slot-renderer', 
                        'ytd-promoted-video-renderer',
                        'ytd-banner-promo-renderer',
                        'ytd-video-masthead-ad-v3-renderer',
                        'ytd-carousel-ad-renderer'
                    ];
                    
                    adSelectors.forEach(selector => {
                        document.querySelectorAll(selector).forEach(el => {
                            el.style.display = 'none';
                            el.style.height = '0';
                            el.style.overflow = 'hidden';
                        });
                    });
                } catch(e) {}
            };
            
            removeSponsoredElements();
            
            try {
                const observer = new MutationObserver(() => {
                    removeSponsoredElements();
                    fixLiveStream();
                });
                if (document.documentElement) {
                    observer.observe(document.documentElement, {
                        childList: true,
                        subtree: true
                    });
                }
            } catch(e) {}
            
        } catch(e) {
            // Ignoruj błędy
        }
    };
    
    // =====================================================
    // 4. FUNKCJA LOGOWANIA
    // =====================================================
    const setupLoginButton = () => {
        try {
            const hasSession = () => {
                try {
                    return document.cookie.includes("SID=") || document.cookie.includes("HSID=");
                } catch(e) {
                    return false;
                }
            };
            
            const modifyLoginButtons = () => {
                try {
                    const ytLoginButtons = document.querySelectorAll(
                        'a[href*="accounts.google.com"], ' +
                        'a[href*="ServiceLogin"], ' +
                        'ytd-masthead #buttons a[href*="accounts.google.com"]'
                    );
                    
                    ytLoginButtons.forEach(btn => {
                        if (!btn.dataset.easytubeHooked) {
                            btn.dataset.easytubeHooked = 'true';
                            btn.style.color = '#1E90FF';
                            btn.style.fontWeight = 'bold';
                            
                            btn.addEventListener('click', (e) => {
                                if (!hasSession()) {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    alert("Aby się zalogować, użyj niebieskiego przycisku 'ZALOGUJ SIĘ ▼' na górnym pasku aplikacji EasyTube!");
                                }
                            }, true);
                        }
                    });
                } catch(e) {}
            };
            
            modifyLoginButtons();
            
            try {
                const loginObserver = new MutationObserver(() => {
                    modifyLoginButtons();
                });
                if (document.documentElement) {
                    loginObserver.observe(document.documentElement, {
                        childList: true,
                        subtree: true
                    });
                }
            } catch(e) {}
            
        } catch(e) {
            // Ignoruj błędy
        }
    };
    
    // =====================================================
    // 5. GŁÓWNA FUNKCJA INICJALIZUJĄCA
    // =====================================================
    const initialize = () => {
        try {
            // Sprawdź czy dokument jest gotowy
            if (!document || !document.documentElement) {
                setTimeout(initialize, 50);
                return;
            }
            
            // Naprawa live
            fixLiveStream();
            
            // Uruchom AdGuard z opóźnieniem
            setTimeout(() => {
                try { runAdGuard(); } catch(e) {}
            }, 500);
            
            // Uruchom blokowanie banerów
            setTimeout(() => {
                try { blockSponsoredBanners(); } catch(e) {}
            }, 600);
            
            // Uruchom funkcję logowania
            setTimeout(() => {
                try { setupLoginButton(); } catch(e) {}
            }, 700);
            
            // Okresowe czyszczenie
            setInterval(() => {
                if (adblockEnabled) {
                    try { fixLiveStream(); } catch(e) {}
                    try {
                        const video = document.querySelector('video');
                        if (video && video.paused && video.src && video.src.includes('live')) {
                            video.play().catch(() => {});
                        }
                    } catch(e) {}
                }
            }, 1000);
            
        } catch(e) {
            // Jeśli wystąpił błąd, spróbuj ponownie
            setTimeout(initialize, 100);
        }
    };
    
    // =====================================================
    // START
    // =====================================================
    
    // Sprawdź czy dokument jest gotowy
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        initialize();
    } else {
        document.addEventListener('DOMContentLoaded', initialize);
        // Zabezpieczenie - jeśli DOMContentLoaded nie zadziała
        setTimeout(initialize, 1000);
    }
    
})();
