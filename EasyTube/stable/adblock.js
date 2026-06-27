// =====================================================
// EasyTube AdBlock - CIĄGŁE BLOKOWANIE REKLAM
// =====================================================

(function() {
    'use strict';
    
    // Sprawdź czy blokowanie reklam jest włączone
    const adblockEnabled = window.__easytube_adblock_enabled !== false;
    
    if (!adblockEnabled) {
        const elements = document.querySelectorAll('#block-youtube-ads-logo, #block-youtube-ads-style, #easytube-sponsored-blocks');
        elements.forEach(el => el.remove());
        return;
    }
    
    // =====================================================
    // 1. CIĄGŁE BLOKOWANIE REKLAM - GŁÓWNA FUNKCJA
    // =====================================================
    
    function blockAllAds() {
        try {
            // --- BLOKOWANIE REKLAM W FILMIE ---
            // Pomijanie reklam
            const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button, .ytp-ad-skip-button-slot, button.ytp-ad-skip-button-renderer');
            if (skipBtn && skipBtn.offsetParent !== null) {
                skipBtn.click();
                console.log('[AdBlock] Pominięto reklamę');
            }
            
            // Przyspieszanie reklam które nie mają przycisku "Pomiń"
            const adShowing = document.querySelector('.ad-showing, .ad-interrupting');
            if (adShowing) {
                const video = document.querySelector('video');
                if (video && video.duration) {
                    video.currentTime = video.duration;
                    console.log('[AdBlock] Przyspieszono reklamę');
                }
            }
            
            // Usuwanie nakładek reklamowych
            const overlays = document.querySelectorAll(
                '.ytp-ad-overlay-container, .ytp-ad-image-overlay, .ytp-ad-action-interstitial, ' +
                '.ytp-ad-text-overlay, .ytp-ad-progress, .ytp-ad-progress-list, ' +
                '.ytp-ad-skip-button-container, .ytp-ad-overlay-slot, .ytp-ad-player-overlay'
            );
            overlays.forEach(el => {
                if (el && el.style) {
                    el.style.display = 'none';
                    el.style.visibility = 'hidden';
                    el.style.opacity = '0';
                    el.style.height = '0';
                    el.style.overflow = 'hidden';
                    el.style.pointerEvents = 'none';
                }
            });
            
            // --- BLOKOWANIE REKLAM NA STRONIE GŁÓWNEJ ---
            // Ukrywanie kontenerów z reklamami
            const adSelectors = [
                'ytd-ad-slot-renderer',
                'ytd-display-ad-renderer',
                'ytd-promoted-video-renderer',
                'ytd-compact-promoted-video-renderer',
                'ytd-video-masthead-ad-v3-renderer',
                'ytd-banner-promo-renderer',
                'ytd-carousel-ad-renderer',
                'ytd-search-pyv-renderer',
                'ytd-promoted-sparkles-web-renderer',
                'ytd-promoted-sparkles-text-search-renderer',
                'ytd-merch-shelf-renderer',
                'ytd-companion-slot-renderer',
                '.companion-ad-container',
                '.promoted-videos',
                '#player-ads',
                '#masthead-ad',
                '#feed-pyv-container',
                '#shelf-pyv-container',
                '#pla-shelf',
                '#merch-shelf'
            ];
            
            adSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(el => {
                    if (el && el.style) {
                        el.style.display = 'none';
                        el.style.visibility = 'hidden';
                        el.style.opacity = '0';
                        el.style.height = '0';
                        el.style.minHeight = '0';
                        el.style.maxHeight = '0';
                        el.style.overflow = 'hidden';
                        el.style.pointerEvents = 'none';
                        el.style.margin = '0';
                        el.style.padding = '0';
                    }
                });
            });
            
            // Ukrywanie kontenerów rich-item z reklamami
            document.querySelectorAll('ytd-rich-item-renderer').forEach(el => {
                if (el.querySelector('ytd-display-ad-renderer, ytd-ad-slot-renderer, ytd-promoted-video-renderer, ytd-compact-promoted-video-renderer')) {
                    el.style.display = 'none';
                    el.style.height = '0';
                    el.style.overflow = 'hidden';
                    el.style.padding = '0';
                    el.style.margin = '0';
                }
            });
            
        } catch(e) {
            // Ignoruj błędy
        }
    }
    
    // =====================================================
    // 2. USUWANIE KOMUNIKATU O NIEOBSŁUGIWANEJ PRZEGLĄDARCE
    // =====================================================
    
    function removeUnsupportedBrowserMessage() {
        try {
            const selectors = [
                '.ytp-unsupported-browser-overlay',
                '.ytp-unsupported-browser',
                '.ytp-error-message',
                '.ytp-error-content',
                '.ytp-error',
                '.ytp-error-screen'
            ];
            
            selectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(el => {
                    if (el && el.style) {
                        el.style.display = 'none';
                        el.style.visibility = 'hidden';
                        el.style.opacity = '0';
                        el.style.height = '0';
                        el.style.overflow = 'hidden';
                    }
                });
            });
        } catch(e) {}
    }
    
    // =====================================================
    // 3. STYLE BLOKUJĄCE - DODAWANE RAZ
    // =====================================================
    
    function addBlockingStyles() {
        if (document.getElementById('easytube-adblock-styles')) {
            return;
        }
        
        const style = document.createElement('style');
        style.id = 'easytube-adblock-styles';
        style.textContent = `
            /* Blokowanie reklam w filmach */
            .ytp-ad-overlay-container,
            .ytp-ad-image-overlay,
            .ytp-ad-action-interstitial,
            .ytp-ad-text-overlay,
            .ytp-ad-progress,
            .ytp-ad-progress-list,
            .ytp-ad-skip-button-container,
            .ytp-ad-overlay-slot,
            .ytp-ad-player-overlay,
            .ytp-ad-action-interstitial-background-container,
            .ytp-ad-action-interstitial-slot,
            .ad-showing,
            .ad-interrupting {
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
            
            /* Blokowanie reklam na stronie głównej */
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
            #player-ads,
            #masthead-ad,
            #feed-pyv-container,
            #shelf-pyv-container,
            #pla-shelf,
            #merch-shelf,
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
            
            /* Ukrywanie kontenerów z reklamami */
            ytd-rich-item-renderer:has(ytd-display-ad-renderer),
            ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
            ytd-rich-item-renderer:has(ytd-promoted-video-renderer),
            ytd-rich-item-renderer:has(ytd-compact-promoted-video-renderer) {
                display: none !important;
                height: 0 !important;
                min-height: 0 !important;
                max-height: 0 !important;
                overflow: hidden !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            
            /* Usuwanie komunikatu o nieobsługiwanej przeglądarce */
            .ytp-unsupported-browser-overlay,
            .ytp-unsupported-browser,
            .ytp-error-message,
            .ytp-error-content,
            .ytp-error,
            .ytp-error-screen {
                display: none !important;
                opacity: 0 !important;
                visibility: hidden !important;
                height: 0 !important;
                min-height: 0 !important;
                max-height: 0 !important;
                overflow: hidden !important;
                pointer-events: none !important;
            }
        `;
        document.head.appendChild(style);
    }
    
    // =====================================================
    // 4. INICJALIZACJA
    // =====================================================
    
    function initialize() {
        try {
            if (!document || !document.head) {
                setTimeout(initialize, 100);
                return;
            }
            
            // Dodaj style blokujące
            addBlockingStyles();
            
            // Uruchom blokowanie od razu
            blockAllAds();
            removeUnsupportedBrowserMessage();
            
            // CIĄGŁE MONITOROWANIE - co 200ms
            setInterval(() => {
                if (window.__easytube_adblock_enabled !== false) {
                    blockAllAds();
                    removeUnsupportedBrowserMessage();
                }
            }, 200);
            
            // OBSERWATOR ZMIAN DOM
            const observer = new MutationObserver(() => {
                if (window.__easytube_adblock_enabled !== false) {
                    blockAllAds();
                    removeUnsupportedBrowserMessage();
                }
            });
            
            // Obserwuj cały dokument
            observer.observe(document.documentElement, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['style', 'class']
            });
            
            console.log('[AdBlock] Aktywny - ciągłe blokowanie reklam');
            
        } catch(e) {
            console.error('[AdBlock] Błąd inicjalizacji:', e);
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
