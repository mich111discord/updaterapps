// =====================================================
// EasyTube LITE MODE - Oszczędzanie transferu danych
// =====================================================

(function() {
    'use strict';
    
    // Sprawdź czy tryb Lite jest włączony
    const liteEnabled = window.__easytube_lite_enabled === true;
    
    if (!liteEnabled) {
        // Usuń style lite jeśli wyłączone
        const style = document.getElementById('easytube-lite-styles');
        if (style) style.remove();
        return;
    }
    
    // =====================================================
    // 1. STYLE BLOKUJĄCE - Oszczędzanie transferu
    // =====================================================
    
    function addLiteStyles() {
        if (document.getElementById('easytube-lite-styles')) {
            return;
        }
        
        const style = document.createElement('style');
        style.id = 'easytube-lite-styles';
        style.textContent = `
            /* ===== BLOKOWANIE AWATARÓW I ZDJĘĆ ===== */
            /* Awatary użytkowników */
            yt-img-shadow,
            #avatar,
            #author-thumbnail,
            .ytp-title-channel-avatar,
            #avatar-container,
            ytd-channel-avatar-editor,
            .channel-thumbnail-icon,
            ytd-comment-renderer #author-thumbnail,
            ytd-comment-renderer .ytd-comment-renderer #avatar,
            ytd-comment-thread-renderer #author-thumbnail,
            .ytd-comment-renderer .ytd-comment-renderer #avatar,
            .ytd-video-owner-renderer .ytd-video-owner-renderer #avatar,
            ytd-video-owner-renderer #avatar,
            ytd-channel-name #avatar,
            ytd-channel-name yt-img-shadow,
            ytd-video-owner-renderer yt-img-shadow,
            ytd-comment-renderer yt-img-shadow,
            ytd-comment-thread-renderer yt-img-shadow,
            ytd-guide-entry-renderer yt-img-shadow,
            ytd-guide-collapsible-section-entry-renderer yt-img-shadow,
            ytd-guide-renderer yt-img-shadow,
            ytd-rich-item-renderer yt-img-shadow,
            ytd-grid-video-renderer yt-img-shadow,
            ytd-video-renderer yt-img-shadow,
            .ytd-video-renderer .ytd-video-renderer #avatar,
            .ytd-grid-video-renderer .ytd-grid-video-renderer #avatar,
            .ytd-rich-item-renderer .ytd-rich-item-renderer #avatar,
            .ytd-rich-grid-renderer .ytd-rich-item-renderer #avatar {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                width: 0px !important;
                height: 0px !important;
                min-width: 0px !important;
                min-height: 0px !important;
                max-width: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* Zdjęcia z ggpht.com (Google Photos) */
            img[src*="ggpht.com"],
            img[src*="googleusercontent.com"],
            img[src*="ytimg.com"]:not([src*="logo"]):not([src*="icon"]),
            img[src*="i.ytimg.com"]:not([src*="logo"]):not([src*="icon"]) {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                width: 0px !important;
                height: 0px !important;
                min-width: 0px !important;
                min-height: 0px !important;
                max-width: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* Emoji i ikony */
            img.emoji,
            .yt-emoji-icon,
            yt-icon.ytd-comment-reactions-v2-button-renderer,
            yt-icon.ytd-badge-supported-renderer,
            ytd-guide-entry-renderer yt-icon,
            ytd-topbar-logo-renderer #logo-icon,
            yt-icon,
            .yt-icon,
            ytd-badge-renderer,
            .ytd-badge-renderer {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                width: 0px !important;
                height: 0px !important;
                min-width: 0px !important;
                min-height: 0px !important;
                max-width: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* ===== BLOKOWANIE MINIATUR ===== */
            /* Miniatury filmów */
            ytd-thumbnail,
            .ytd-thumbnail,
            #thumbnail,
            .ytp-cued-thumbnail-overlay,
            .ytp-cued-thumbnail,
            .ytp-thumbnail,
            .ytd-video-renderer #thumbnail,
            .ytd-grid-video-renderer #thumbnail,
            .ytd-rich-item-renderer #thumbnail,
            .ytd-playlist-renderer #thumbnail,
            ytd-playlist-renderer #thumbnail,
            ytd-rich-playlist-renderer #thumbnail,
            ytd-video-preview-renderer #thumbnail,
            .ytd-video-preview-renderer #thumbnail {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                width: 0px !important;
                height: 0px !important;
                min-width: 0px !important;
                min-height: 0px !important;
                max-width: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* ===== BLOKOWANIE CZCIONEK Z ZEWNĄTRZ ===== */
            /* Blokowanie fontów Google */
            @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap') {
                display: none !important;
            }
            
            /* Blokowanie fontów z gstatic */
            link[href*="fonts.gstatic.com"],
            link[href*="fonts.googleapis.com"],
            style[href*="fonts.googleapis.com"] {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                pointer-events: none !important;
            }
            
            /* ===== BLOKOWANIE NIEISTOTNYCH ELEMENTÓW ===== */
            /* Komentarze */
            ytd-comment-renderer,
            ytd-comment-thread-renderer,
            .ytd-comment-renderer,
            .ytd-comment-thread-renderer,
            #comments,
            .ytd-comments-renderer,
            ytd-comments-renderer {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0px !important;
                min-height: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* Pasek boczny (przewodnik) */
            ytd-guide-renderer,
            ytd-guide-section-renderer,
            #guide,
            .ytd-guide-renderer {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                width: 0px !important;
                min-width: 0px !important;
                max-width: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* Suplementy i polecane */
            #related,
            .ytd-watch-next-secondary-results-renderer,
            ytd-watch-next-secondary-results-renderer,
            .ytd-compact-video-renderer,
            ytd-compact-video-renderer,
            #items.ytd-watch-next-secondary-results-renderer {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0px !important;
                min-height: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* Banery i reklamy (dodatkowe) */
            ytd-banner-renderer,
            ytd-banner-promo-renderer,
            ytd-merch-shelf-renderer,
            ytd-carousel-ad-renderer,
            .ytd-banner-renderer,
            #masthead-ad,
            #player-ads,
            ytd-display-ad-renderer,
            ytd-ad-slot-renderer,
            ytd-promoted-video-renderer,
            ytd-compact-promoted-video-renderer {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0px !important;
                min-height: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* ===== ZWIĘKSZENIE WIDOCZNOŚCI TREŚCI ===== */
            /* Główna treść na pełnej szerokości */
            #player-container-outer,
            #player-container,
            .html5-video-player,
            #movie_player,
            .ytd-watch-flexy,
            ytd-watch-flexy {
                width: 100% !important;
                max-width: 100% !important;
                min-width: 100% !important;
                margin: 0 !important;
                padding: 0 !important;
            }
            
            #player-container-outer {
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            
            /* Tytuł filmu */
            #title.ytd-watch-metadata,
            .ytd-watch-metadata #title,
            ytd-watch-metadata #title {
                font-size: 18px !important;
                font-weight: bold !important;
                color: #fff !important;
                margin: 10px 0 !important;
            }
            
            /* Opis filmu - skrócony */
            #description,
            .ytd-watch-metadata #description,
            ytd-watch-metadata #description {
                font-size: 13px !important;
                color: #aaa !important;
                max-height: 60px !important;
                overflow: hidden !important;
                margin: 5px 0 !important;
            }
            
            /* Przyciski interakcji - mniejsze */
            #top-level-buttons,
            .ytd-watch-metadata #top-level-buttons,
            ytd-watch-metadata #top-level-buttons {
                display: flex !important;
                gap: 5px !important;
                flex-wrap: wrap !important;
            }
            
            #top-level-buttons ytd-button-renderer {
                min-width: auto !important;
                padding: 2px 8px !important;
                font-size: 12px !important;
            }
            
            /* ===== OPTYMALIZACJA SZUKANIA ===== */
            /* Ukrywanie filtrów wyszukiwania */
            #filters,
            .ytd-search #filters,
            ytd-search #filters {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
            }
            
            /* Ukrywanie sugestii wyszukiwania */
            .ytd-searchbox-suggestions,
            ytd-searchbox-suggestions {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                pointer-events: none !important;
            }
            
            /* ===== OSZCZĘDZANIE TRANSFERU - BLOKOWANIE ZAPYTAŃ ===== */
            /* Blokowanie niepotrzebnych zapytań przez interceptor */
            .ytd-searchbox-suggestions,
            ytd-searchbox-suggestions,
            #searchbox-suggestions,
            .ytd-searchbox-suggestions {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                pointer-events: none !important;
            }
            
            /* ===== UKRYWANIE NIEISTOTNYCH ELEMENTÓW STRONY ===== */
            /* Kanały, subskrypcje, trendy w pasku bocznym */
            #guide #sections,
            #guide .ytd-guide-section-renderer,
            #guide ytd-guide-section-renderer {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0px !important;
                min-height: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
            }
            
            /* Krótkie filmiki (Shorts) - w trybie Lite niepotrzebne */
            ytd-reel-shelf-renderer,
            ytd-shorts-shelf-renderer,
            .ytd-reel-shelf-renderer,
            .ytd-shorts-shelf-renderer,
            #reel-shelf,
            .ytd-rich-shelf-renderer[is-shorts] {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0px !important;
                min-height: 0px !important;
                max-height: 0px !important;
                overflow: hidden !important;
                pointer-events: none !important;
            }
            
            /* Kafelki "Nowe filmy" */
            ytd-shelf-renderer,
            .ytd-shelf-renderer {
                margin: 5px 0 !important;
                padding: 5px 0 !important;
            }
            
            ytd-shelf-renderer #title {
                font-size: 14px !important;
            }
            
            /* ===== PRZYSPIESZENIE ŁADOWANIA ===== */
            /* Mniej animacji */
            * {
                transition-duration: 0.001s !important;
                animation-duration: 0.001s !important;
                animation-iteration-count: 1 !important;
            }
            
            /* Ukrywanie elementów "Pokaż więcej" */
            #more,
            .ytd-expander #more,
            ytd-expander #more,
            #less,
            .ytd-expander #less,
            ytd-expander #less {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                pointer-events: none !important;
            }
        `;
        document.head.appendChild(style);
    }
    
    // =====================================================
    // 2. USUWANIE NIEISTOTNYCH ZASOBÓW
    // =====================================================
    
    function removeUnnecessaryResources() {
        try {
            // Usuwanie niepotrzebnych skryptów analitycznych
            const scripts = document.querySelectorAll('script[src*="analytics"], script[src*="measurement"], script[src*="tagmanager"]');
            scripts.forEach(el => {
                if (el && el.parentNode) {
                    el.remove();
                }
            });
            
            // Usuwanie niepotrzebnych iframe
            const iframes = document.querySelectorAll('iframe[src*="doubleclick"], iframe[src*="googleads"], iframe[src*="googlesyndication"]');
            iframes.forEach(el => {
                if (el && el.parentNode) {
                    el.remove();
                }
            });
            
        } catch(e) {}
    }
    
    // =====================================================
    // 3. BLOKOWANIE ZAPYTAŃ O NIEISTOTNE ZASOBY
    // =====================================================
    
    function blockRequests() {
        try {
            // Blokowanie zapytań do niepotrzebnych serwisów
            const originalFetch = window.fetch;
            window.fetch = function(url, options) {
                if (typeof url === 'string') {
                    if (url.includes('googleapis.com') && !url.includes('youtubei')) {
                        return Promise.reject(new Error('Blocked by Lite mode'));
                    }
                    if (url.includes('google-analytics.com') || url.includes('googletagmanager.com')) {
                        return Promise.reject(new Error('Blocked by Lite mode'));
                    }
                    if (url.includes('fonts.googleapis.com') || url.includes('fonts.gstatic.com')) {
                        return Promise.reject(new Error('Blocked by Lite mode'));
                    }
                    if (url.includes('ggpht.com') || url.includes('googleusercontent.com')) {
                        if (!url.includes('logo') && !url.includes('icon')) {
                            return Promise.reject(new Error('Blocked by Lite mode'));
                        }
                    }
                }
                return originalFetch.call(this, url, options);
            };
            
            // Blokowanie XMLHttpRequest
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                if (typeof url === 'string') {
                    if (url.includes('googleapis.com') && !url.includes('youtubei')) {
                        return;
                    }
                    if (url.includes('google-analytics.com') || url.includes('googletagmanager.com')) {
                        return;
                    }
                    if (url.includes('fonts.googleapis.com') || url.includes('fonts.gstatic.com')) {
                        return;
                    }
                    if (url.includes('ggpht.com') || url.includes('googleusercontent.com')) {
                        if (!url.includes('logo') && !url.includes('icon')) {
                            return;
                        }
                    }
                }
                return originalOpen.call(this, method, url, async, user, password);
            };
            
        } catch(e) {}
    }
    
    // =====================================================
    // 4. CIĄGŁE MONITOROWANIE
    // =====================================================
    
    function cleanLiteMode() {
        try {
            // Dodatkowe usuwanie dynamicznie dodawanych elementów
            document.querySelectorAll('yt-img-shadow, #avatar, #author-thumbnail, .ytp-title-channel-avatar').forEach(el => {
                if (el && el.style) {
                    el.style.display = 'none';
                    el.style.visibility = 'hidden';
                    el.style.width = '0';
                    el.style.height = '0';
                    el.style.overflow = 'hidden';
                }
            });
            
            document.querySelectorAll('img[src*="ggpht.com"], img[src*="googleusercontent.com"]').forEach(el => {
                if (el && el.style) {
                    el.style.display = 'none';
                    el.style.visibility = 'hidden';
                    el.style.width = '0';
                    el.style.height = '0';
                    el.style.overflow = 'hidden';
                }
            });
            
            // Usuwanie nowo dodanych komentarzy
            document.querySelectorAll('ytd-comment-renderer, ytd-comment-thread-renderer, #comments').forEach(el => {
                if (el && el.style) {
                    el.style.display = 'none';
                    el.style.visibility = 'hidden';
                    el.style.height = '0';
                    el.style.overflow = 'hidden';
                }
            });
            
        } catch(e) {}
    }
    
    // =====================================================
    // 5. INICJALIZACJA
    // =====================================================
    
    function initialize() {
        try {
            if (!document || !document.head) {
                setTimeout(initialize, 100);
                return;
            }
            
            // Dodaj style
            addLiteStyles();
            
            // Usuń niepotrzebne zasoby
            removeUnnecessaryResources();
            
            // Blokuj zapytania
            blockRequests();
            
            // Uruchom czyszczenie od razu
            cleanLiteMode();
            
            // CIĄGŁE MONITOROWANIE - co 500ms
            setInterval(() => {
                if (window.__easytube_lite_enabled === true) {
                    cleanLiteMode();
                }
            }, 500);
            
            // OBSERWATOR ZMIAN DOM
            const observer = new MutationObserver(() => {
                if (window.__easytube_lite_enabled === true) {
                    cleanLiteMode();
                }
            });
            
            observer.observe(document.documentElement, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['style', 'class']
            });
            
            console.log('[Lite Mode] Aktywny - oszczędzanie transferu danych');
            
        } catch(e) {
            console.error('[Lite Mode] Błąd inicjalizacji:', e);
            setTimeout(initialize, 500);
        }
    }
    
    // =====================================================
    // START
    // =====================================================
    
    if (document.readyState === 'complete') {
        setTimeout(initialize, 300);
    } else {
        window.addEventListener('load', function() {
            setTimeout(initialize, 300);
        });
    }
    
})();
