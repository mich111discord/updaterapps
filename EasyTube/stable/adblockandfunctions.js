// =====================================================
// EasyTube AdBlock - ZABEZPIECZONA WERSJA
// =====================================================

// GŁÓWNA FUNKCJA - OPAKOWANA W TRY/CATCH
(function() {
    'use strict';
    
    // Funkcja do bezpiecznego sprawdzania czy dokument jest gotowy
    function isDocumentReady() {
        return document && document.documentElement && document.head && document.body;
    }
    
    // Funkcja do bezpiecznego dodawania stylów
    function safeAddStyle(id, css) {
        try {
            if (!document || !document.head) return false;
            if (document.getElementById(id)) return true;
            const style = document.createElement('style');
            style.id = id;
            style.textContent = css;
            document.head.appendChild(style);
            return true;
        } catch(e) {
            return false;
        }
    }
    
    // Funkcja do bezpiecznego usuwania elementów
    function safeRemoveElements(selector) {
        try {
            if (!document) return;
            document.querySelectorAll(selector).forEach(el => {
                if (el && el.parentNode) {
                    try { el.remove(); } catch(e) {}
                }
            });
        } catch(e) {}
    }
    
    // =====================================================
    // 1. NAPRAWA LIVE - USUŃ KOMUNIKATY O BŁĘDACH
    // =====================================================
    function fixLiveStream() {
        try {
            if (!document) return;
            
            // Usuń elementy błędów
            const selectors = [
                '.ytp-unsupported-browser-overlay',
                '.ytp-unsupported-browser', 
                '.ytp-error-message',
                '.ytp-error-content',
                '.ytp-error',
                '.ytp-error-screen',
                '.ytp-error-overlay',
                '.ytp-error-overlay-container',
                '.ytp-error-overlay-content',
                '.ytp-playback-error',
                '[class*="unsupported"]',
                '[class*="error-screen"]'
            ];
            
            selectors.forEach(selector => {
                try {
                    document.querySelectorAll(selector).forEach(el => {
                        if (el && el.style) {
                            el.style.display = 'none';
                            el.style.visibility = 'hidden';
                            el.style.opacity = '0';
                            el.style.height = '0';
                            el.style.overflow = 'hidden';
                            el.style.pointerEvents = 'none';
                            if (el.parentNode) {
                                try { el.remove(); } catch(e) {}
                            }
                        }
                    });
                } catch(e) {}
            });
            
            // Dodaj styl tylko raz
            safeAddStyle('easytube-live-fix', `
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
            `);
            
            // Spróbuj odtworzyć wideo
            try {
                const video = document.querySelector('video');
                if (video && video.paused && video.src) {
                    video.play().catch(() => {});
                }
            } catch(e) {}
            
        } catch(e) {}
    }
    
    // =====================================================
    // 2. BLOKOWANIE REKLAM - UPROSZCZONA WERSJA
    // =====================================================
    function blockAds() {
        try {
            if (!document || !document.head) return;
            
            // GŁÓWNE STYLE BLOKUJĄCE REKLAMY
            safeAddStyle('easytube-adblock-styles', `
                /* Blokowanie reklam w filmach */
                .ytp-ad-overlay-container,
                .ytp-ad-image-overlay,
                .ytp-ad-action-interstitial,
                .ytp-ad-text-overlay,
                .ytp-ad-progress,
                .ytp-ad-progress-list,
                .ytp-ad-skip-button-container,
                .ytp-ad-visit-advertiser-button,
                .ytp-ad-image-overlay-container,
                .ytp-ad-action-interstitial-background-container,
                .ytp-ad-action-interstitial-slot,
                .ytp-ad-overlay-container:not(:empty),
                .ytp-ad-player-overlay,
                .ytp-ad-overlay-slot,
                .ad-showing,
                .ad-interrupting,
                #player-ads,
                #masthead-ad,
                ytd-ad-slot-renderer,
                ytd-display-ad-renderer,
                ytd-promoted-video-renderer,
                ytd-compact-promoted-video-renderer,
                ytd-video-masthead-ad-v3-renderer,
                ytd-banner-promo-renderer,
                ytd-carousel-ad-renderer,
                ytd-search-pyv-renderer,
                ytd-promoted-sparkles-web-renderer,
                ytd-promoted-sparkles-text-search-renderer,
                ytd-merch-shelf-renderer,
                ytd-companion-slot-renderer,
                .companion-ad-container,
                .promoted-videos,
                .promoted-sparkles-text-search-root-container,
                #feed-pyv-container,
                #shelf-pyv-container,
                #pla-shelf,
                #merch-shelf,
                #offer-module,
                #video-masthead,
                #watch-branded-actions,
                [class*="ytd-display-ad-"],
                [class*="display-ad-"],
                [class*="ad-container"],
                [class*="ad-badge"],
                [class*="sponsored"],
                [class*="promoted"] {
                    display: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                    height: 0 !important;
                    min-height: 0 !important;
                    max-height: 0 !important;
                    overflow: hidden !important;
                    pointer-events: none !important;
                    margin: 0 !important;
                    padding: 0 !important;
                }
                
                /* Ukryj kontenery z reklamami */
                ytd-rich-item-renderer:has(ytd-display-ad-renderer),
                ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
                ytd-rich-item-renderer:has(ytd-promoted-video-renderer) {
                    display: none !important;
                    height: 0 !important;
                    min-height: 0 !important;
                    max-height: 0 !important;
                    overflow: hidden !important;
                    padding: 0 !important;
                    margin: 0 !important;
                }
            `);
            
            // AUTOMATYCZNE POMIJANIE REKLAM
            function autoSkipAds() {
                try {
                    const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button');
                    if (skipBtn && skipBtn.offsetParent !== null) {
                        skipBtn.click();
                        return;
                    }
                    
                    if (document.querySelector('.ad-showing, .ad-interrupting')) {
                        const video = document.querySelector('video');
                        if (video && video.duration) {
                            video.currentTime = video.duration;
                        }
                    }
                } catch(e) {}
            }
            
            // Uruchom pomijanie
            autoSkipAds();
            
            // Obserwuj zmiany
            try {
                const observer = new MutationObserver(() => {
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
            
        } catch(e) {}
    }
    
    // =====================================================
    // 3. BLOKOWANIE BANERÓW NA STRONIE GŁÓWNEJ
    // =====================================================
    function blockHomeBanners() {
        try {
            if (!document) return;
            
            function removeBanners() {
                try {
                    // Usuń banery sponsorowane
                    document.querySelectorAll('ytd-rich-item-renderer').forEach(el => {
                        if (el.querySelector('ytd-display-ad-renderer, ytd-ad-slot-renderer, ytd-promoted-video-renderer')) {
                            el.style.display = 'none';
                            el.style.height = '0';
                            el.style.overflow = 'hidden';
                            el.style.padding = '0';
                            el.style.margin = '0';
                        }
                    });
                    
                    // Usuń elementy reklamowe
                    const selectors = [
                        'ytd-display-ad-renderer',
                        'ytd-ad-slot-renderer',
                        'ytd-promoted-video-renderer',
                        'ytd-banner-promo-renderer',
                        'ytd-video-masthead-ad-v3-renderer',
                        'ytd-carousel-ad-renderer',
                        'ytd-merch-shelf-renderer'
                    ];
                    
                    selectors.forEach(selector => {
                        document.querySelectorAll(selector).forEach(el => {
                            if (el && el.style) {
                                el.style.display = 'none';
                                el.style.height = '0';
                                el.style.overflow = 'hidden';
                            }
                        });
                    });
                } catch(e) {}
            }
            
            removeBanners();
            
            try {
                const observer = new MutationObserver(() => {
                    removeBanners();
                    fixLiveStream();
                });
                if (document.documentElement) {
                    observer.observe(document.documentElement, {
                        childList: true,
                        subtree: true
                    });
                }
            } catch(e) {}
            
        } catch(e) {}
    }
    
    // =====================================================
    // 4. FUNKCJA LOGOWANIA
    // =====================================================
    function setupLogin() {
        try {
            if (!document) return;
            
            function hasSession() {
                try {
                    return document.cookie.includes('SID=') || document.cookie.includes('HSID=');
                } catch(e) {
                    return false;
                }
            }
            
            function modifyButtons() {
                try {
                    document.querySelectorAll('a[href*="accounts.google.com"], a[href*="ServiceLogin"]').forEach(btn => {
                        if (!btn.dataset.easytubeHooked) {
                            btn.dataset.easytubeHooked = 'true';
                            btn.style.color = '#1E90FF';
                            btn.style.fontWeight = 'bold';
                            btn.addEventListener('click', function(e) {
                                if (!hasSession()) {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    alert("Aby się zalogować, użyj niebieskiego przycisku 'ZALOGUJ SIĘ ▼' na górnym pasku aplikacji EasyTube!");
                                }
                            }, true);
                        }
                    });
                } catch(e) {}
            }
            
            modifyButtons();
            
            try {
                const observer = new MutationObserver(modifyButtons);
                if (document.documentElement) {
                    observer.observe(document.documentElement, {
                        childList: true,
                        subtree: true
                    });
                }
            } catch(e) {}
            
        } catch(e) {}
    }
    
    // =====================================================
    // 5. FUNKCJA INICJUJĄCA
    // =====================================================
    function initialize() {
        try {
            // Sprawdź czy dokument jest gotowy
            if (!isDocumentReady()) {
                setTimeout(initialize, 100);
                return;
            }
            
            // Najpierw naprawa live
            fixLiveStream();
            
            // Potem blokowanie reklam
            setTimeout(() => {
                try { blockAds(); } catch(e) {}
            }, 300);
            
            // Blokowanie banerów
            setTimeout(() => {
                try { blockHomeBanners(); } catch(e) {}
            }, 500);
            
            // Funkcja logowania
            setTimeout(() => {
                try { setupLogin(); } catch(e) {}
            }, 700);
            
            // Okresowe czyszczenie
            if (window.__easytube_interval) {
                clearInterval(window.__easytube_interval);
            }
            
            window.__easytube_interval = setInterval(() => {
                try {
                    if (window.__easytube_adblock_enabled !== false) {
                        fixLiveStream();
                        
                        // Spróbuj odtworzyć wideo live
                        const video = document.querySelector('video');
                        if (video && video.paused && video.src && video.src.includes('live')) {
                            video.play().catch(() => {});
                        }
                    }
                } catch(e) {}
            }, 2000);
            
        } catch(e) {
            setTimeout(initialize, 200);
        }
    }
    
    // =====================================================
    // START - CZEKAJ NA PEŁNE ZAŁADOWANIE STRONY
    // =====================================================
    
    // Sprawdź czy dokument jest w pełni załadowany
    if (document.readyState === 'complete') {
        setTimeout(initialize, 500);
    } else {
        // Czekaj na pełne załadowanie
        window.addEventListener('load', function() {
            setTimeout(initialize, 500);
        });
        
        // Zabezpieczenie - jeśli load nie zadziała
        setTimeout(function() {
            if (!window.__easytube_initialized) {
                window.__easytube_initialized = true;
                initialize();
            }
        }, 3000);
    }
    
})();
