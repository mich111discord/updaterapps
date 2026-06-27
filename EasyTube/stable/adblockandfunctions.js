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
    // 1. NAPRAWA DLA TRANSMISJI NA ŻYWO (LIVE) - CAŁKOWITE USUNIĘCIE KOMUNIKATÓW
    // =====================================================
    const fixLiveStream = () => {
        // Usuń WSZYSTKIE elementy związane z błędami i komunikatami
        const removeSelectors = [
            // Komunikaty o nieobsługiwanej przeglądarce
            '.ytp-unsupported-browser-overlay',
            '.ytp-unsupported-browser',
            '.ytp-error-message',
            '.ytp-error-content',
            '.ytp-error',
            '.ytp-error-screen',
            '.ytp-error .ytp-error-content',
            '.ytp-error .ytp-error-text',
            '.ytp-error .ytp-error-message',
            '.ytp-error .ytp-error-screen',
            '.ytp-error .ytp-error-content-renderer',
            
            // Wszystkie elementy z błędami
            '[class*="unsupported"]',
            '[class*="error-screen"]',
            '[class*="error-message"]',
            '[class*="error-content"]',
            '[class*="browser-not-supported"]',
            
            // Nakładki błędów
            '.ytp-error-overlay',
            '.ytp-error-overlay-container',
            '.ytp-error-overlay-content',
            
            // Komunikaty o problemach z odtwarzaniem
            '.ytp-playback-error',
            '.ytp-playback-error-message',
            '.ytp-playback-error-content',
            
            // Wszystko co zawiera tekst o błędzie
            '[class*="error"]:not(.ytp-chrome-controls):not(.ytp-progress-bar)',
            '[class*="unsupported"]:not(.ytp-chrome-controls)'
        ];
        
        removeSelectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(el => {
                // Usuń całkowicie element
                if (el.parentNode) {
                    el.parentNode.style.display = 'block';
                    el.parentNode.style.visibility = 'visible';
                    el.parentNode.style.opacity = '1';
                }
                el.style.display = 'none';
                el.style.visibility = 'hidden';
                el.style.opacity = '0';
                el.style.height = '0';
                el.style.minHeight = '0';
                el.style.maxHeight = '0';
                el.style.overflow = 'hidden';
                el.style.pointerEvents = 'none';
                el.style.position = 'absolute';
                el.style.top = '-9999px';
                el.style.left = '-9999px';
                // Usuń z DOM
                try { el.remove(); } catch(e) {}
            });
        });
        
        // Usuń elementy z tekstem o błędzie
        document.querySelectorAll('*').forEach(el => {
            if (el.textContent && (
                el.textContent.includes('Nie możesz odtworzyć') ||
                el.textContent.includes('Cannot play') ||
                el.textContent.includes('browser') ||
                el.textContent.includes('unsupported') ||
                el.textContent.includes('not supported') ||
                el.textContent.includes('w swojej przeglądarce') ||
                el.textContent.includes('przeglądarka nie jest obsługiwana') ||
                el.textContent.includes('This browser is not supported') ||
                el.textContent.includes('browser is not supported')
            )) {
                // Sprawdź czy to nie jest ważny element (np. controls)
                if (!el.closest('.ytp-chrome-controls') && 
                    !el.closest('.ytp-progress-bar') &&
                    !el.closest('.ytp-volume-panel') &&
                    !el.closest('.ytp-fullscreen-button')) {
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
            }
        });
        
        // Dodaj styl dla live - całkowicie usuwa komunikaty
        if (!document.getElementById('easytube-live-fix')) {
            const style = document.createElement('style');
            style.id = 'easytube-live-fix';
            style.textContent = `
                /* Całkowite usunięcie komunikatów błędów */
                .ytp-unsupported-browser-overlay,
                .ytp-unsupported-browser,
                .ytp-error-message,
                .ytp-error-content,
                .ytp-error,
                .ytp-error-screen,
                .ytp-error .ytp-error-content,
                .ytp-error .ytp-error-text,
                .ytp-error .ytp-error-message,
                .ytp-error .ytp-error-screen,
                .ytp-error-overlay,
                .ytp-error-overlay-container,
                .ytp-error-overlay-content,
                .ytp-playback-error,
                .ytp-playback-error-message,
                .ytp-playback-error-content,
                [class*="unsupported"]:not(.ytp-chrome-controls),
                [class*="error-screen"]:not(.ytp-chrome-controls),
                [class*="error-message"]:not(.ytp-chrome-controls),
                [class*="error-content"]:not(.ytp-chrome-controls) {
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
                
                /* Ukryj tło z komunikatem */
                .ytp-error-screen {
                    display: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                }
                
                /* Naprawa dla odtwarzacza live */
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
                
                /* Ukryj napisy o błędzie w tle */
                .ytp-error-content-renderer {
                    display: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                }
            `;
            document.head.appendChild(style);
        }
        
        // Spróbuj odtworzyć wideo jeśli jest zatrzymane
        const video = document.querySelector('video');
        if (video) {
            // Usuń atrybuty blokujące
            video.removeAttribute('disablepictureinpicture');
            video.removeAttribute('disableremoteplayback');
            
            // Jeśli wideo jest zatrzymane, spróbuj odtworzyć
            if (video.paused && video.src) {
                video.play().catch(() => {});
            }
            
            // Ustaw crossOrigin dla lepszej kompatybilności
            if (video.src && video.src.includes('live')) {
                video.setAttribute('crossorigin', 'anonymous');
            }
            
            // Usuń atrybuty powodujące błędy
            video.removeAttribute('poster');
        }
        
        // Usuń wszystkie nakładki błędów
        document.querySelectorAll('.ytp-error, .ytp-error-screen, .ytp-error .ytp-error-content, .ytp-error-overlay').forEach(el => {
            el.style.display = 'none';
            el.style.opacity = '0';
            el.style.visibility = 'hidden';
            el.style.height = '0';
            el.style.minHeight = '0';
            el.style.maxHeight = '0';
            el.style.overflow = 'hidden';
            try { el.remove(); } catch(e) {}
        });
    };
    
    // =====================================================
    // 2. ADGUARD - BLOKOWANIE REKLAM W FILMACH
    // =====================================================
    const runAdGuard = () => {
        const locales = {
            en: {
                logo: "with&nbsp;AdGuard",
                alreadyExecuted: "The shortcut has already been executed.",
                wrongDomain: "This shortcut is supposed to be launched only on YouTube.",
                success: "YouTube is now ad-free! Please note that you need to run this shortcut again if you reload the page."
            },
            ru: {
                logo: "с&nbsp;AdGuard",
                alreadyExecuted: "Быстрая команда уже выполнена.",
                wrongDomain: "Эта быстрая команда предназначена для использования только на YouTube.",
                success: "Теперь YouTube без рекламы! Важно: при перезагрузке страницы вам нужно будет заново запустить команду."
            },
            es: {
                logo: "con&nbsp;AdGuard",
                alreadyExecuted: "El atajo ya ha sido ejecutado.",
                wrongDomain: "Se supone que este atajo se lanza sólo en YouTube.",
                success: "¡YouTube está ahora libre de anuncios! Ten en cuenta que tienes que volver a ejecutar este atajo si recargas la página."
            },
            de: {
                logo: "mit&nbsp;AdGuard",
                alreadyExecuted: "Der Kurzbefehl wurde bereits ausgeführt.",
                wrongDomain: "Dieser Kurzbefehl soll nur auf YouTube gestartet werden.",
                success: "YouTube ist jetzt werbefrei! Bitte beachten Sie, dass Sie diesen Kurzbefehl erneut ausführen müssen, wenn Sie die Seite neu laden."
            },
            fr: {
                logo: "avec&nbsp;AdGuard",
                alreadyExecuted: "Le raccourci a déjà été exécuté.",
                wrongDomain: "Ce raccourci est censé d'être lancé uniquement sur YouTube.",
                success: "YouTube est maintenant libre de pub ! Veuillez noter qu'il faudra rééxecuter le raccourci si vous rechargez la page."
            },
            ar: {
                logo: "مع&nbsp;AdGuard",
                alreadyExecuted: "تم تنفيذ الاختصار بالفعل.",
                wrongDomain: "من المفترض أن يتم تشغيل هذا الاختصار على YouTube فقط.",
                success: "أصبح YouTube الآن خاليًا من الإعلانات! يرجى ملاحظة أنك ستحتاج إلى إعادة تشغيل الاختصار إذا قمت بإعادة تحميل الصفحة."
            },
            it: {
                logo: "con&nbsp;AdGuard",
                alreadyExecuted: "Il comando è già stato eseguito.",
                wrongDomain: "Questa scorciatoia dovrebbe essere lanciata solo su YouTube.",
                success: "YouTube è ora libero da pubblicità! Si prega di notare che è necessario eseguire nuovamente questa scorciatoia se ricarichi la pagina."
            },
            "zh-cn": {
                logo: "使用&nbsp;AdGuard",
                alreadyExecuted: "快捷指令已在运行",
                wrongDomain: "快捷指令只能在 YouTube 上被启动。",
                success: "现在您的 YouTube 没有广告！请注意，若您重新加载页面，您需要再次启动快捷指令。"
            },
            "zh-tw": {
                logo: "偕同&nbsp;AdGuard",
                alreadyExecuted: "此捷徑已被執行。",
                wrongDomain: "此捷徑應該只於 YouTube 上被啟動。",
                success: "現在 YouTube 為無廣告的！請注意，若您重新載入該頁面，您需要再次執行此捷徑。"
            },
            ko: {
                logo: "AdGuard&nbsp;사용",
                alreadyExecuted: "단축어가 이미 실행되었습니다.",
                wrongDomain: "이 단축어는 YouTube에서만 사용 가능합니다.",
                success: "이제 광고없이 YouTube를 시청할 수 있습니다. 페이지를 새로고침 할 경우, 이 단축어를 다시 실행해야 합니다."
            },
            ja: {
                logo: "AdGuard作動中",
                alreadyExecuted: "ショートカットは既に実行されています。",
                wrongDomain: "※このショートカットは、YouTubeでのみ適用されることを想定しています。",
                success: "YouTubeが広告なしになりました！※YouTubeページを再読み込みした場合は、このショートカットを再度実行する必要がありますのでご注意ください。"
            },
            uk: {
                logo: "з&nbsp;AdGuard",
                alreadyExecuted: "Ця швидка команда вже виконується.",
                wrongDomain: "Цю швидку команду слід запускати лише на YouTube.",
                success: "Тепер YouTube без реклами! Проте після перезавантаження сторінки необхідно знову запустити цю швидку команду."
            }
        };
        
        const getMessage = (key) => {
            try {
                let locale = locales[navigator.language.toLowerCase()];
                if (!locale) {
                    const lang = navigator.language.split("-")[0];
                    locale = locales[lang];
                }
                if (!locale) {
                    locale = locales.en;
                }
                return locale[key];
            } catch (ex) {
                return locales.en[key];
            }
        };
        
        if (document.getElementById("block-youtube-ads-logo")) {
            return {
                success: false,
                status: "alreadyExecuted",
                message: getMessage("alreadyExecuted")
            };
        }
        
        if (window.location.hostname !== "www.youtube.com" && window.location.hostname !== "m.youtube.com" && window.location.hostname !== "music.youtube.com") {
            return {
                success: false,
                status: "wrongDomain",
                message: getMessage("wrongDomain")
            };
        }
        
        const pageScript = () => {
            const LOGO_ID = "block-youtube-ads-logo";
            const hiddenCSS = {
                "www.youtube.com": [
                    "#__ffYoutube1",
                    "#__ffYoutube2",
                    "#__ffYoutube3",
                    "#__ffYoutube4",
                    "#feed-pyv-container",
                    "#feedmodule-PRO",
                    "#homepage-chrome-side-promo",
                    "#merch-shelf",
                    "#offer-module",
                    '#pla-shelf > ytd-pla-shelf-renderer[class="style-scope ytd-watch"]',
                    "#pla-shelf",
                    "#premium-yva",
                    "#promo-info",
                    "#promo-list",
                    "#promotion-shelf",
                    "#related > ytd-watch-next-secondary-results-renderer > #items > ytd-compact-promoted-video-renderer.ytd-watch-next-secondary-results-renderer",
                    "#search-pva",
                    "#shelf-pyv-container",
                    "#video-masthead",
                    "#watch-branded-actions",
                    "#watch-buy-urls",
                    "#watch-channel-brand-div",
                    "#watch7-branded-banner",
                    "#YtKevlarVisibilityIdentifier",
                    "#YtSparklesVisibilityIdentifier",
                    ".carousel-offer-url-container",
                    ".companion-ad-container",
                    ".GoogleActiveViewElement",
                    '.list-view[style="margin: 7px 0pt;"]',
                    ".promoted-sparkles-text-search-root-container",
                    ".promoted-videos",
                    ".searchView.list-view",
                    ".sparkles-light-cta",
                    ".watch-extra-info-column",
                    ".watch-extra-info-right",
                    ".ytd-carousel-ad-renderer",
                    ".ytd-compact-promoted-video-renderer",
                    ".ytd-companion-slot-renderer",
                    ".ytd-merch-shelf-renderer",
                    ".ytd-player-legacy-desktop-watch-ads-renderer",
                    ".ytd-promoted-sparkles-text-search-renderer",
                    ".ytd-promoted-video-renderer",
                    ".ytd-search-pyv-renderer",
                    ".ytd-video-masthead-ad-v3-renderer",
                    ".ytp-ad-action-interstitial-background-container",
                    ".ytp-ad-action-interstitial-slot",
                    ".ytp-ad-image-overlay",
                    ".ytp-ad-overlay-container",
                    ".ytp-ad-progress",
                    ".ytp-ad-progress-list",
                    '[class*="ytd-display-ad-"]',
                    '[layout*="display-ad-"]',
                    'a[href^="http://www.youtube.com/cthru?"]',
                    'a[href^="https://www.youtube.com/cthru?"]',
                    "ytd-action-companion-ad-renderer",
                    "ytd-banner-promo-renderer",
                    "ytd-compact-promoted-video-renderer",
                    "ytd-companion-slot-renderer",
                    "ytd-display-ad-renderer",
                    "ytd-promoted-sparkles-text-search-renderer",
                    "ytd-promoted-sparkles-web-renderer",
                    "ytd-search-pyv-renderer",
                    "ytd-single-option-survey-renderer",
                    "ytd-video-masthead-ad-advertiser-info-renderer",
                    "ytd-video-masthead-ad-v3-renderer",
                    "YTM-PROMOTED-VIDEO-RENDERER"
                ],
                "m.youtube.com": [
                    ".companion-ad-container",
                    ".ytp-ad-action-interstitial",
                    '.ytp-cued-thumbnail-overlay > div[style*="/sddefault.jpg"]',
                    `a[href^="/watch?v="][onclick^="return koya.onEvent(arguments[0]||window.event,'"]:not([role]):not([class]):not([id])`,
                    `a[onclick*='"ping_url":"http://www.google.com/aclk?']`,
                    "ytm-companion-ad-renderer",
                    "ytm-companion-slot",
                    "ytm-promoted-sparkles-text-search-renderer",
                    "ytm-promoted-sparkles-web-renderer",
                    "ytm-promoted-video-renderer"
                ]
            };
            
            const hideElements = (hostname) => {
                const selectors = hiddenCSS[hostname];
                if (!selectors) {
                    return;
                }
                const rule = `${selectors.join(", ")} { display: none!important; }`;
                const style = document.createElement("style");
                style.id = 'block-youtube-ads-style';
                style.innerHTML = rule;
                document.head.appendChild(style);
            };
            
            const observeDomChanges = (callback) => {
                const domMutationObserver = new MutationObserver((mutations) => {
                    callback(mutations);
                });
                domMutationObserver.observe(document.documentElement, {
                    childList: true,
                    subtree: true
                });
            };
            
            const hideDynamicAds = () => {
                const elements = document.querySelectorAll("#contents > ytd-rich-item-renderer ytd-display-ad-renderer");
                if (elements.length === 0) {
                    return;
                }
                elements.forEach((el) => {
                    if (el.parentNode && el.parentNode.parentNode) {
                        const parent = el.parentNode.parentNode;
                        if (parent.localName === "ytd-rich-item-renderer") {
                            parent.style.display = "none";
                        }
                    }
                });
            };
            
            const autoSkipAds = () => {
                if (document.querySelector(".ad-showing")) {
                    const video = document.querySelector("video");
                    if (video && video.duration) {
                        video.currentTime = video.duration;
                        setTimeout(() => {
                            const skipBtn = document.querySelector("button.ytp-ad-skip-button");
                            if (skipBtn) {
                                skipBtn.click();
                            }
                        }, 100);
                    }
                }
            };
            
            const overrideObject = (obj, propertyName, overrideValue) => {
                if (!obj) {
                    return false;
                }
                let overriden = false;
                for (const key in obj) {
                    if (obj.hasOwnProperty(key) && key === propertyName) {
                        obj[key] = overrideValue;
                        overriden = true;
                    } else if (obj.hasOwnProperty(key) && typeof obj[key] === "object") {
                        if (overrideObject(obj[key], propertyName, overrideValue)) {
                            overriden = true;
                        }
                    }
                }
                if (overriden) {
                    console.log(`found: ${propertyName}`);
                }
                return overriden;
            };
            
            const jsonOverride = (propertyName, overrideValue) => {
                const nativeJSONParse = JSON.parse;
                JSON.parse = (...args) => {
                    const obj = nativeJSONParse.apply(this, args);
                    overrideObject(obj, propertyName, overrideValue);
                    return obj;
                };
                const nativeResponseJson = Response.prototype.json;
                Response.prototype.json = new Proxy(nativeResponseJson, {
                    apply(...args) {
                        const promise = Reflect.apply(args);
                        return new Promise((resolve, reject) => {
                            promise.then((data) => {
                                overrideObject(data, propertyName, overrideValue);
                                resolve(data);
                            }).catch((error) => reject(error));
                        });
                    }
                });
            };
            
            const addAdGuardLogoStyle = () => {
                const id = "block-youtube-ads-logo-style";
                if (document.getElementById(id)) {
                    return;
                }
                const style = document.createElement("style");
                style.innerHTML = `[data-mode="watch"] #${LOGO_ID} { color: #fff; }
[data-mode="searching"] #${LOGO_ID}, [data-mode="search"] #${LOGO_ID} { display: none; }
#${LOGO_ID} { white-space: nowrap; }
.mobile-topbar-header-sign-in-button { display: none; }
.ytmusic-nav-bar#left-content #${LOGO_ID} { display: block; }`;
                document.head.appendChild(style);
            };
            
            const addAdGuardLogo = () => {
                if (document.getElementById(LOGO_ID)) {
                    return;
                }
                const logo = document.createElement("span");
                logo.innerHTML = "__logo_text__";
                logo.setAttribute("id", LOGO_ID);
                if (window.location.hostname === "m.youtube.com") {
                    const btn = document.querySelector("header.mobile-topbar-header > button");
                    if (btn) {
                        btn.parentNode.insertBefore(logo, btn.nextSibling);
                        addAdGuardLogoStyle();
                    }
                } else if (window.location.hostname === "www.youtube.com") {
                    const code = document.getElementById("country-code");
                    if (code) {
                        code.innerHTML = "";
                        code.appendChild(logo);
                        addAdGuardLogoStyle();
                    }
                } else if (window.location.hostname === "music.youtube.com") {
                    const el = document.querySelector(".ytmusic-nav-bar#left-content");
                    if (el) {
                        el.appendChild(logo);
                        addAdGuardLogoStyle();
                    }
                }
            };
            
            jsonOverride("adPlacements", []);
            jsonOverride("playerAds", []);
            hideElements(window.location.hostname);
            addAdGuardLogo();
            hideDynamicAds();
            autoSkipAds();
            observeDomChanges(() => {
                addAdGuardLogo();
                hideDynamicAds();
                autoSkipAds();
                fixLiveStream(); // Dodaj naprawę live przy każdej zmianie DOM
            });
        };
        
        const script = document.createElement("script");
        const scriptText = pageScript.toString().replace("__logo_text__", getMessage("logo"));
        script.innerHTML = `(${scriptText})();`;
        document.head.appendChild(script);
        document.head.removeChild(script);
        
        return {
            success: true,
            status: "success",
            message: getMessage("success")
        };
    };
    
    // =====================================================
    // 3. BLOKOWANIE BANERÓW SPONSOROWANYCH NA STRONIE GŁÓWNEJ
    // =====================================================
    const blockSponsoredBanners = () => {
        // Dodaj style dla banerów sponsorowanych
        if (!document.getElementById('easytube-sponsored-blocks')) {
            const style = document.createElement('style');
            style.id = 'easytube-sponsored-blocks';
            style.textContent = `
                /* Blokowanie banerów sponsorowanych na stronie głównej */
                ytd-rich-item-renderer:has(ytd-display-ad-renderer),
                ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
                ytd-rich-item-renderer:has(ytd-promoted-video-renderer),
                ytd-rich-item-renderer:has(ytd-compact-promoted-video-renderer),
                ytd-rich-item-renderer:has([class*="sponsored"]),
                ytd-rich-item-renderer:has([class*="ad-badge"]),
                ytd-rich-item-renderer:has([class*="promoted"]),
                ytd-rich-item-renderer:has([aria-label*="sponsor"]),
                ytd-rich-item-renderer:has([aria-label*="reklama"]),
                ytd-rich-item-renderer:has([aria-label*="ad"]),
                ytd-rich-item-renderer:has([aria-label*="Advertisement"]),
                
                /* Banery na górze strony */
                ytd-banner-renderer,
                ytd-banner-promo-renderer,
                ytd-merch-shelf-renderer,
                ytd-carousel-ad-renderer,
                ytd-video-masthead-ad-v3-renderer,
                
                /* Elementy w feedzie */
                #contents > ytd-rich-item-renderer > ytd-display-ad-renderer,
                #contents > ytd-rich-item-renderer > ytd-ad-slot-renderer,
                #contents > ytd-rich-item-renderer > ytd-promoted-video-renderer,
                
                /* Ukrywanie elementów z klasami reklamowymi */
                [class*="ad-container"],
                [class*="ad-badge"],
                [class*="sponsored"],
                [class*="promoted"],
                [class*="ad-slot"],
                [class*="display-ad"],
                
                /* Reklamy w wynikach wyszukiwania */
                ytd-search-pyv-renderer,
                ytd-promoted-sparkles-web-renderer,
                ytd-promoted-sparkles-text-search-renderer,
                ytd-single-option-survey-renderer,
                
                /* Ukryj puste miejsca po reklamach */
                ytd-rich-item-renderer:empty,
                ytd-rich-item-renderer[hidden],
                ytd-rich-item-renderer[style*="display: none"] {
                    display: none !important;
                    min-height: 0 !important;
                    max-height: 0 !important;
                    height: 0 !important;
                    overflow: hidden !important;
                    padding: 0 !important;
                    margin: 0 !important;
                }
            `;
            document.head.appendChild(style);
        }
        
        // Funkcja do usuwania dynamicznych banerów
        const removeSponsoredElements = () => {
            // Usuń elementy z atrybutami wskazującymi na reklamy
            document.querySelectorAll('ytd-rich-item-renderer').forEach(el => {
                if (el.querySelector('ytd-display-ad-renderer, ytd-ad-slot-renderer, ytd-promoted-video-renderer, ytd-compact-promoted-video-renderer')) {
                    el.style.display = 'none';
                    el.style.opacity = '0';
                    el.style.visibility = 'hidden';
                    el.style.height = '0';
                    el.style.minHeight = '0';
                    el.style.maxHeight = '0';
                    el.style.overflow = 'hidden';
                    el.style.pointerEvents = 'none';
                    el.style.margin = '0';
                    el.style.padding = '0';
                }
            });
            
            // Usuń bezpośrednio elementy reklamowe
            const adSelectors = [
                'ytd-display-ad-renderer', 
                'ytd-ad-slot-renderer', 
                'ytd-promoted-video-renderer', 
                'ytd-compact-promoted-video-renderer',
                'ytd-banner-promo-renderer',
                'ytd-video-masthead-ad-v3-renderer',
                'ytd-carousel-ad-renderer',
                'ytd-merch-shelf-renderer',
                'ytd-banner-renderer'
            ];
            
            adSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(el => {
                    el.style.display = 'none';
                    el.style.opacity = '0';
                    el.style.visibility = 'hidden';
                    el.style.height = '0';
                    el.style.minHeight = '0';
                    el.style.maxHeight = '0';
                    el.style.overflow = 'hidden';
                    el.style.pointerEvents = 'none';
                    el.style.margin = '0';
                    el.style.padding = '0';
                });
            });
        };
        
        // Uruchom od razu
        removeSponsoredElements();
        
        // Obserwuj zmiany DOM
        const observer = new MutationObserver(() => {
            removeSponsoredElements();
            fixLiveStream(); // Dodaj naprawę live przy każdej zmianie
        });
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    };
    
    // =====================================================
    // 4. FUNKCJA LOGOWANIA - NIEBIESKI PRZYCISK
    // =====================================================
    const setupLoginButton = () => {
        // Funkcja sprawdzająca czy użytkownik jest zalogowany
        const hasSession = () => {
            return document.cookie.includes("SID=") || document.cookie.includes("HSID=");
        };
        
        // Znajdź i zmodyfikuj przyciski logowania
        const modifyLoginButtons = () => {
            const ytLoginButtons = document.querySelectorAll(
                'a[href*="accounts.google.com"], ' +
                'ytd-button-renderer[button-next] a, ' +
                'a[href*="ServiceLogin"], ' +
                'ytd-masthead #buttons ytd-button-renderer, ' +
                '#buttons ytd-button-renderer a, ' +
                'ytd-masthead #buttons a[href*="accounts.google.com"]'
            );
            
            ytLoginButtons.forEach(btn => {
                // Sprawdź czy to przycisk logowania
                const isLoginButton = btn.textContent && (
                    btn.textContent.toLowerCase().includes('zaloguj') ||
                    btn.textContent.toLowerCase().includes('sign in') ||
                    btn.textContent.toLowerCase().includes('login') ||
                    btn.textContent.toLowerCase().includes('log in')
                );
                
                if (isLoginButton || btn.href?.includes('accounts.google.com') || btn.href?.includes('ServiceLogin')) {
                    if (!btn.dataset.easytubeHooked) {
                        btn.dataset.easytubeHooked = 'true';
                        
                        // Dodaj styl niebieskiego przycisku
                        btn.style.color = '#1E90FF';
                        btn.style.fontWeight = 'bold';
                        
                        // Dodaj obsługę kliknięcia
                        btn.addEventListener('click', (e) => {
                            const currentSessionCheck = hasSession();
                            if (!currentSessionCheck) {
                                e.preventDefault();
                                e.stopPropagation();
                                alert("Aby się zalogować, użyj niebieskiego przycisku 'ZALOGUJ SIĘ ▼' na górnym pasku aplikacji EasyTube!");
                            }
                        }, true);
                    }
                }
            });
        };
        
        // Uruchom od razu
        modifyLoginButtons();
        
        // Obserwuj zmiany DOM
        const loginObserver = new MutationObserver(() => {
            modifyLoginButtons();
        });
        loginObserver.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    };
    
    // =====================================================
    // 5. URUCHOM WSZYSTKIE FUNKCJE
    // =====================================================
    
    // Najpierw naprawa live - natychmiast
    fixLiveStream();
    
    // Uruchom AdGuard po krótkim opóźnieniu
    setTimeout(() => {
        try {
            runAdGuard();
        } catch(e) {
            console.log('AdGuard error:', e);
        }
    }, 100);
    
    // Uruchom blokowanie banerów sponsorowanych
    setTimeout(() => {
        try {
            blockSponsoredBanners();
        } catch(e) {
            console.log('Sponsored banners error:', e);
        }
    }, 200);
    
    // Uruchom funkcję logowania
    setTimeout(() => {
        try {
            setupLoginButton();
        } catch(e) {
            console.log('Login button error:', e);
        }
    }, 300);
    
    // Okresowe czyszczenie dla live - co 200ms dla szybkiej reakcji
    setInterval(() => {
        if (adblockEnabled) {
            fixLiveStream();
            
            // Spróbuj odtworzyć wideo live jeśli jest zatrzymane
            const video = document.querySelector('video');
            if (video && video.paused && video.src && video.src.includes('live')) {
                video.play().catch(() => {});
            }
            
            // Usuń komunikaty o błędach
            document.querySelectorAll('.ytp-error-message, .ytp-error-content, .ytp-error, .ytp-error-screen, .ytp-error-overlay, .ytp-error-overlay-container, .ytp-error-overlay-content').forEach(el => {
                el.style.display = 'none';
                el.style.opacity = '0';
                el.style.visibility = 'hidden';
                el.style.height = '0';
                el.style.minHeight = '0';
                el.style.maxHeight = '0';
                el.style.overflow = 'hidden';
                try { el.remove(); } catch(e) {}
            });
        }
    }, 200);
    
})();// =====================================================
// EasyTube AdBlock - Połączenie AdGuard + dodatkowe blokowanie
// =====================================================

(function() {
    // Sprawdź czy blokowanie reklam jest włączone
    const adblockEnabled = window.__easytube_adblock_enabled !== false;
    
    if (!adblockEnabled) {
        // Jeśli wyłączone, usuń elementy blokujące
        const elements = document.querySelectorAll('#block-youtube-ads-logo, #block-youtube-ads-style, #easytube-extra-adblock, #easytube-live-fix');
        elements.forEach(el => el.remove());
        return;
    }
    
    // =====================================================
    // 1. NAPRAWA DLA TRANSMISJI NA ŻYWO (LIVE)
    // =====================================================
    const fixLiveStream = () => {
        // Usuń komunikat o nieobsługiwanej przeglądarce
        const unsupportedSelectors = [
            '.ytp-unsupported-browser-overlay',
            '.ytp-unsupported-browser',
            '.ytp-error-message',
            '.ytp-error-content',
            '.ytp-error',
            '.ytp-error-screen',
            '.ytp-error .ytp-error-content',
            '.ytp-error .ytp-error-text',
            '.ytp-error .ytp-error-message'
        ];
        
        unsupportedSelectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(el => {
                el.style.display = 'none';
                el.style.visibility = 'hidden';
                el.style.opacity = '0';
                el.style.height = '0';
                el.style.minHeight = '0';
                el.style.overflow = 'hidden';
                if (el.parentNode) {
                    el.parentNode.style.display = 'block';
                }
                el.remove();
            });
        });
        
        // Spróbuj odtworzyć wideo jeśli jest zatrzymane
        const video = document.querySelector('video');
        if (video) {
            // Usuń atrybuty blokujące
            video.removeAttribute('disablepictureinpicture');
            video.removeAttribute('disableremoteplayback');
            
            // Jeśli wideo jest zatrzymane, spróbuj odtworzyć
            if (video.paused && video.src) {
                video.play().catch(() => {});
            }
            
            // Ustaw crossOrigin dla lepszej kompatybilności
            if (video.src && video.src.includes('live')) {
                video.setAttribute('crossorigin', 'anonymous');
            }
        }
        
        // Usuń nakładki błędów
        document.querySelectorAll('.ytp-error, .ytp-error-screen, .ytp-error .ytp-error-content').forEach(el => {
            el.style.display = 'none';
            el.style.opacity = '0';
            el.style.visibility = 'hidden';
        });
        
        // Ukryj elementy z komunikatem o błędzie
        document.querySelectorAll('[class*="error"]').forEach(el => {
            if (el.textContent && (el.textContent.includes('Nie możesz odtworzyć') || 
                el.textContent.includes('Cannot play') || 
                el.textContent.includes('browser'))) {
                el.style.display = 'none';
                el.style.opacity = '0';
                el.style.visibility = 'hidden';
            }
        });
        
        // Dodaj styl dla live
        if (!document.getElementById('easytube-live-fix')) {
            const style = document.createElement('style');
            style.id = 'easytube-live-fix';
            style.textContent = `
                /* Naprawa dla transmisji na żywo */
                .ytp-unsupported-browser-overlay,
                .ytp-unsupported-browser,
                .ytp-error-message,
                .ytp-error-content,
                .ytp-error,
                .ytp-error-screen,
                .ytp-error .ytp-error-content,
                .ytp-error .ytp-error-text,
                .ytp-error .ytp-error-message,
                [class*="unsupported"],
                [class*="error-screen"] {
                    display: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                    height: 0 !important;
                    min-height: 0 !important;
                    overflow: hidden !important;
                    pointer-events: none !important;
                }
                
                /* Naprawa dla odtwarzacza live */
                #movie_player {
                    display: block !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                }
                
                #movie_player video {
                    display: block !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                }
                
                .html5-video-player {
                    display: block !important;
                    visibility: visible !important;
                    opacity: 1 !important;
                }
            `;
            document.head.appendChild(style);
        }
    };
    
    // =====================================================
    // 2. ADGUARD - BLOKOWANIE REKLAM W FILMACH
    // =====================================================
    const runAdGuard = () => {
        const locales = {
            en: {
                logo: "with&nbsp;AdGuard",
                alreadyExecuted: "The shortcut has already been executed.",
                wrongDomain: "This shortcut is supposed to be launched only on YouTube.",
                success: "YouTube is now ad-free! Please note that you need to run this shortcut again if you reload the page."
            },
            ru: {
                logo: "с&nbsp;AdGuard",
                alreadyExecuted: "Быстрая команда уже выполнена.",
                wrongDomain: "Эта быстрая команда предназначена для использования только на YouTube.",
                success: "Теперь YouTube без рекламы! Важно: при перезагрузке страницы вам нужно будет заново запустить команду."
            },
            es: {
                logo: "con&nbsp;AdGuard",
                alreadyExecuted: "El atajo ya ha sido ejecutado.",
                wrongDomain: "Se supone que este atajo se lanza sólo en YouTube.",
                success: "¡YouTube está ahora libre de anuncios! Ten en cuenta que tienes que volver a ejecutar este atajo si recargas la página."
            },
            de: {
                logo: "mit&nbsp;AdGuard",
                alreadyExecuted: "Der Kurzbefehl wurde bereits ausgeführt.",
                wrongDomain: "Dieser Kurzbefehl soll nur auf YouTube gestartet werden.",
                success: "YouTube ist jetzt werbefrei! Bitte beachten Sie, dass Sie diesen Kurzbefehl erneut ausführen müssen, wenn Sie die Seite neu laden."
            },
            fr: {
                logo: "avec&nbsp;AdGuard",
                alreadyExecuted: "Le raccourci a déjà été exécuté.",
                wrongDomain: "Ce raccourci est censé d'être lancé uniquement sur YouTube.",
                success: "YouTube est maintenant libre de pub ! Veuillez noter qu'il faudra rééxecuter le raccourci si vous rechargez la page."
            },
            ar: {
                logo: "مع&nbsp;AdGuard",
                alreadyExecuted: "تم تنفيذ الاختصار بالفعل.",
                wrongDomain: "من المفترض أن يتم تشغيل هذا الاختصار على YouTube فقط.",
                success: "أصبح YouTube الآن خاليًا من الإعلانات! يرجى ملاحظة أنك ستحتاج إلى إعادة تشغيل الاختصار إذا قمت بإعادة تحميل الصفحة."
            },
            it: {
                logo: "con&nbsp;AdGuard",
                alreadyExecuted: "Il comando è già stato eseguito.",
                wrongDomain: "Questa scorciatoia dovrebbe essere lanciata solo su YouTube.",
                success: "YouTube è ora libero da pubblicità! Si prega di notare che è necessario eseguire nuovamente questa scorciatoia se ricarichi la pagina."
            },
            "zh-cn": {
                logo: "使用&nbsp;AdGuard",
                alreadyExecuted: "快捷指令已在运行",
                wrongDomain: "快捷指令只能在 YouTube 上被启动。",
                success: "现在您的 YouTube 没有广告！请注意，若您重新加载页面，您需要再次启动快捷指令。"
            },
            "zh-tw": {
                logo: "偕同&nbsp;AdGuard",
                alreadyExecuted: "此捷徑已被執行。",
                wrongDomain: "此捷徑應該只於 YouTube 上被啟動。",
                success: "現在 YouTube 為無廣告的！請注意，若您重新載入該頁面，您需要再次執行此捷徑。"
            },
            ko: {
                logo: "AdGuard&nbsp;사용",
                alreadyExecuted: "단축어가 이미 실행되었습니다.",
                wrongDomain: "이 단축어는 YouTube에서만 사용 가능합니다.",
                success: "이제 광고없이 YouTube를 시청할 수 있습니다. 페이지를 새로고침 할 경우, 이 단축어를 다시 실행해야 합니다."
            },
            ja: {
                logo: "AdGuard作動中",
                alreadyExecuted: "ショートカットは既に実行されています。",
                wrongDomain: "※このショートカットは、YouTubeでのみ適用されることを想定しています。",
                success: "YouTubeが広告なしになりました！※YouTubeページを再読み込みした場合は、このショートカットを再度実行する必要がありますのでご注意ください。"
            },
            uk: {
                logo: "з&nbsp;AdGuard",
                alreadyExecuted: "Ця швидка команда вже виконується.",
                wrongDomain: "Цю швидку команду слід запускати лише на YouTube.",
                success: "Тепер YouTube без реклами! Проте після перезавантаження сторінки необхідно знову запустити цю швидку команду."
            }
        };
        
        const getMessage = (key) => {
            try {
                let locale = locales[navigator.language.toLowerCase()];
                if (!locale) {
                    const lang = navigator.language.split("-")[0];
                    locale = locales[lang];
                }
                if (!locale) {
                    locale = locales.en;
                }
                return locale[key];
            } catch (ex) {
                return locales.en[key];
            }
        };
        
        if (document.getElementById("block-youtube-ads-logo")) {
            return {
                success: false,
                status: "alreadyExecuted",
                message: getMessage("alreadyExecuted")
            };
        }
        
        if (window.location.hostname !== "www.youtube.com" && window.location.hostname !== "m.youtube.com" && window.location.hostname !== "music.youtube.com") {
            return {
                success: false,
                status: "wrongDomain",
                message: getMessage("wrongDomain")
            };
        }
        
        const pageScript = () => {
            const LOGO_ID = "block-youtube-ads-logo";
            const hiddenCSS = {
                "www.youtube.com": [
                    "#__ffYoutube1",
                    "#__ffYoutube2",
                    "#__ffYoutube3",
                    "#__ffYoutube4",
                    "#feed-pyv-container",
                    "#feedmodule-PRO",
                    "#homepage-chrome-side-promo",
                    "#merch-shelf",
                    "#offer-module",
                    '#pla-shelf > ytd-pla-shelf-renderer[class="style-scope ytd-watch"]',
                    "#pla-shelf",
                    "#premium-yva",
                    "#promo-info",
                    "#promo-list",
                    "#promotion-shelf",
                    "#related > ytd-watch-next-secondary-results-renderer > #items > ytd-compact-promoted-video-renderer.ytd-watch-next-secondary-results-renderer",
                    "#search-pva",
                    "#shelf-pyv-container",
                    "#video-masthead",
                    "#watch-branded-actions",
                    "#watch-buy-urls",
                    "#watch-channel-brand-div",
                    "#watch7-branded-banner",
                    "#YtKevlarVisibilityIdentifier",
                    "#YtSparklesVisibilityIdentifier",
                    ".carousel-offer-url-container",
                    ".companion-ad-container",
                    ".GoogleActiveViewElement",
                    '.list-view[style="margin: 7px 0pt;"]',
                    ".promoted-sparkles-text-search-root-container",
                    ".promoted-videos",
                    ".searchView.list-view",
                    ".sparkles-light-cta",
                    ".watch-extra-info-column",
                    ".watch-extra-info-right",
                    ".ytd-carousel-ad-renderer",
                    ".ytd-compact-promoted-video-renderer",
                    ".ytd-companion-slot-renderer",
                    ".ytd-merch-shelf-renderer",
                    ".ytd-player-legacy-desktop-watch-ads-renderer",
                    ".ytd-promoted-sparkles-text-search-renderer",
                    ".ytd-promoted-video-renderer",
                    ".ytd-search-pyv-renderer",
                    ".ytd-video-masthead-ad-v3-renderer",
                    ".ytp-ad-action-interstitial-background-container",
                    ".ytp-ad-action-interstitial-slot",
                    ".ytp-ad-image-overlay",
                    ".ytp-ad-overlay-container",
                    ".ytp-ad-progress",
                    ".ytp-ad-progress-list",
                    '[class*="ytd-display-ad-"]',
                    '[layout*="display-ad-"]',
                    'a[href^="http://www.youtube.com/cthru?"]',
                    'a[href^="https://www.youtube.com/cthru?"]',
                    "ytd-action-companion-ad-renderer",
                    "ytd-banner-promo-renderer",
                    "ytd-compact-promoted-video-renderer",
                    "ytd-companion-slot-renderer",
                    "ytd-display-ad-renderer",
                    "ytd-promoted-sparkles-text-search-renderer",
                    "ytd-promoted-sparkles-web-renderer",
                    "ytd-search-pyv-renderer",
                    "ytd-single-option-survey-renderer",
                    "ytd-video-masthead-ad-advertiser-info-renderer",
                    "ytd-video-masthead-ad-v3-renderer",
                    "YTM-PROMOTED-VIDEO-RENDERER"
                ],
                "m.youtube.com": [
                    ".companion-ad-container",
                    ".ytp-ad-action-interstitial",
                    '.ytp-cued-thumbnail-overlay > div[style*="/sddefault.jpg"]',
                    `a[href^="/watch?v="][onclick^="return koya.onEvent(arguments[0]||window.event,'"]:not([role]):not([class]):not([id])`,
                    `a[onclick*='"ping_url":"http://www.google.com/aclk?']`,
                    "ytm-companion-ad-renderer",
                    "ytm-companion-slot",
                    "ytm-promoted-sparkles-text-search-renderer",
                    "ytm-promoted-sparkles-web-renderer",
                    "ytm-promoted-video-renderer"
                ]
            };
            
            const hideElements = (hostname) => {
                const selectors = hiddenCSS[hostname];
                if (!selectors) {
                    return;
                }
                const rule = `${selectors.join(", ")} { display: none!important; }`;
                const style = document.createElement("style");
                style.id = 'block-youtube-ads-style';
                style.innerHTML = rule;
                document.head.appendChild(style);
            };
            
            const observeDomChanges = (callback) => {
                const domMutationObserver = new MutationObserver((mutations) => {
                    callback(mutations);
                });
                domMutationObserver.observe(document.documentElement, {
                    childList: true,
                    subtree: true
                });
            };
            
            const hideDynamicAds = () => {
                const elements = document.querySelectorAll("#contents > ytd-rich-item-renderer ytd-display-ad-renderer");
                if (elements.length === 0) {
                    return;
                }
                elements.forEach((el) => {
                    if (el.parentNode && el.parentNode.parentNode) {
                        const parent = el.parentNode.parentNode;
                        if (parent.localName === "ytd-rich-item-renderer") {
                            parent.style.display = "none";
                        }
                    }
                });
            };
            
            const autoSkipAds = () => {
                if (document.querySelector(".ad-showing")) {
                    const video = document.querySelector("video");
                    if (video && video.duration) {
                        video.currentTime = video.duration;
                        setTimeout(() => {
                            const skipBtn = document.querySelector("button.ytp-ad-skip-button");
                            if (skipBtn) {
                                skipBtn.click();
                            }
                        }, 100);
                    }
                }
            };
            
            const overrideObject = (obj, propertyName, overrideValue) => {
                if (!obj) {
                    return false;
                }
                let overriden = false;
                for (const key in obj) {
                    if (obj.hasOwnProperty(key) && key === propertyName) {
                        obj[key] = overrideValue;
                        overriden = true;
                    } else if (obj.hasOwnProperty(key) && typeof obj[key] === "object") {
                        if (overrideObject(obj[key], propertyName, overrideValue)) {
                            overriden = true;
                        }
                    }
                }
                if (overriden) {
                    console.log(`found: ${propertyName}`);
                }
                return overriden;
            };
            
            const jsonOverride = (propertyName, overrideValue) => {
                const nativeJSONParse = JSON.parse;
                JSON.parse = (...args) => {
                    const obj = nativeJSONParse.apply(this, args);
                    overrideObject(obj, propertyName, overrideValue);
                    return obj;
                };
                const nativeResponseJson = Response.prototype.json;
                Response.prototype.json = new Proxy(nativeResponseJson, {
                    apply(...args) {
                        const promise = Reflect.apply(args);
                        return new Promise((resolve, reject) => {
                            promise.then((data) => {
                                overrideObject(data, propertyName, overrideValue);
                                resolve(data);
                            }).catch((error) => reject(error));
                        });
                    }
                });
            };
            
            const addAdGuardLogoStyle = () => {
                const id = "block-youtube-ads-logo-style";
                if (document.getElementById(id)) {
                    return;
                }
                const style = document.createElement("style");
                style.innerHTML = `[data-mode="watch"] #${LOGO_ID} { color: #fff; }
[data-mode="searching"] #${LOGO_ID}, [data-mode="search"] #${LOGO_ID} { display: none; }
#${LOGO_ID} { white-space: nowrap; }
.mobile-topbar-header-sign-in-button { display: none; }
.ytmusic-nav-bar#left-content #${LOGO_ID} { display: block; }`;
                document.head.appendChild(style);
            };
            
            const addAdGuardLogo = () => {
                if (document.getElementById(LOGO_ID)) {
                    return;
                }
                const logo = document.createElement("span");
                logo.innerHTML = "__logo_text__";
                logo.setAttribute("id", LOGO_ID);
                if (window.location.hostname === "m.youtube.com") {
                    const btn = document.querySelector("header.mobile-topbar-header > button");
                    if (btn) {
                        btn.parentNode.insertBefore(logo, btn.nextSibling);
                        addAdGuardLogoStyle();
                    }
                } else if (window.location.hostname === "www.youtube.com") {
                    const code = document.getElementById("country-code");
                    if (code) {
                        code.innerHTML = "";
                        code.appendChild(logo);
                        addAdGuardLogoStyle();
                    }
                } else if (window.location.hostname === "music.youtube.com") {
                    const el = document.querySelector(".ytmusic-nav-bar#left-content");
                    if (el) {
                        el.appendChild(logo);
                        addAdGuardLogoStyle();
                    }
                }
            };
            
            jsonOverride("adPlacements", []);
            jsonOverride("playerAds", []);
            hideElements(window.location.hostname);
            addAdGuardLogo();
            hideDynamicAds();
            autoSkipAds();
            observeDomChanges(() => {
                addAdGuardLogo();
                hideDynamicAds();
                autoSkipAds();
                fixLiveStream(); // Dodaj naprawę live przy każdej zmianie DOM
            });
        };
        
        const script = document.createElement("script");
        const scriptText = pageScript.toString().replace("__logo_text__", getMessage("logo"));
        script.innerHTML = `(${scriptText})();`;
        document.head.appendChild(script);
        document.head.removeChild(script);
        
        return {
            success: true,
            status: "success",
            message: getMessage("success")
        };
    };
    
    // =====================================================
    // 3. BLOKOWANIE BANERÓW SPONSOROWANYCH NA STRONIE GŁÓWNEJ
    // =====================================================
    const blockSponsoredBanners = () => {
        // Dodaj style dla banerów sponsorowanych
        if (!document.getElementById('easytube-sponsored-blocks')) {
            const style = document.createElement('style');
            style.id = 'easytube-sponsored-blocks';
            style.textContent = `
                /* Blokowanie banerów sponsorowanych na stronie głównej */
                ytd-rich-item-renderer:has(ytd-display-ad-renderer),
                ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
                ytd-rich-item-renderer:has(ytd-promoted-video-renderer),
                ytd-rich-item-renderer:has(ytd-compact-promoted-video-renderer),
                ytd-rich-item-renderer:has([class*="sponsored"]),
                ytd-rich-item-renderer:has([class*="ad-badge"]),
                ytd-rich-item-renderer:has([class*="promoted"]),
                ytd-rich-item-renderer:has([aria-label*="sponsor"]),
                ytd-rich-item-renderer:has([aria-label*="reklama"]),
                ytd-rich-item-renderer:has([aria-label*="ad"]),
                ytd-rich-item-renderer:has([aria-label*="Advertisement"]),
                
                /* Banery na górze strony */
                ytd-banner-renderer,
                ytd-banner-promo-renderer,
                ytd-merch-shelf-renderer,
                ytd-carousel-ad-renderer,
                ytd-video-masthead-ad-v3-renderer,
                
                /* Elementy w feedzie */
                #contents > ytd-rich-item-renderer > ytd-display-ad-renderer,
                #contents > ytd-rich-item-renderer > ytd-ad-slot-renderer,
                #contents > ytd-rich-item-renderer > ytd-promoted-video-renderer,
                
                /* Ukrywanie elementów z klasami reklamowymi */
                [class*="ad-container"],
                [class*="ad-badge"],
                [class*="sponsored"],
                [class*="promoted"],
                [class*="ad-slot"],
                [class*="display-ad"],
                
                /* Reklamy w wynikach wyszukiwania */
                ytd-search-pyv-renderer,
                ytd-promoted-sparkles-web-renderer,
                ytd-promoted-sparkles-text-search-renderer,
                ytd-single-option-survey-renderer,
                
                /* Ukryj puste miejsca po reklamach */
                ytd-rich-item-renderer:empty,
                ytd-rich-item-renderer[hidden],
                ytd-rich-item-renderer[style*="display: none"] {
                    display: none !important;
                    min-height: 0 !important;
                    max-height: 0 !important;
                    height: 0 !important;
                    overflow: hidden !important;
                    padding: 0 !important;
                    margin: 0 !important;
                }
            `;
            document.head.appendChild(style);
        }
        
        // Funkcja do usuwania dynamicznych banerów
        const removeSponsoredElements = () => {
            // Usuń elementy z atrybutami wskazującymi na reklamy
            document.querySelectorAll('ytd-rich-item-renderer').forEach(el => {
                if (el.querySelector('ytd-display-ad-renderer, ytd-ad-slot-renderer, ytd-promoted-video-renderer, ytd-compact-promoted-video-renderer')) {
                    el.style.display = 'none';
                    el.style.opacity = '0';
                    el.style.visibility = 'hidden';
                    el.style.height = '0';
                    el.style.minHeight = '0';
                    el.style.maxHeight = '0';
                    el.style.overflow = 'hidden';
                    el.style.pointerEvents = 'none';
                    el.style.margin = '0';
                    el.style.padding = '0';
                }
            });
            
            // Usuń bezpośrednio elementy reklamowe
            const adSelectors = [
                'ytd-display-ad-renderer', 
                'ytd-ad-slot-renderer', 
                'ytd-promoted-video-renderer', 
                'ytd-compact-promoted-video-renderer',
                'ytd-banner-promo-renderer',
                'ytd-video-masthead-ad-v3-renderer',
                'ytd-carousel-ad-renderer',
                'ytd-merch-shelf-renderer',
                'ytd-banner-renderer'
            ];
            
            adSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(el => {
                    el.style.display = 'none';
                    el.style.opacity = '0';
                    el.style.visibility = 'hidden';
                    el.style.height = '0';
                    el.style.minHeight = '0';
                    el.style.maxHeight = '0';
                    el.style.overflow = 'hidden';
                    el.style.pointerEvents = 'none';
                    el.style.margin = '0';
                    el.style.padding = '0';
                });
            });
        };
        
        // Uruchom od razu
        removeSponsoredElements();
        
        // Obserwuj zmiany DOM
        const observer = new MutationObserver(() => {
            removeSponsoredElements();
            fixLiveStream(); // Dodaj naprawę live przy każdej zmianie
        });
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    };
    
    // =====================================================
    // 4. URUCHOM WSZYSTKIE FUNKCJE
    // =====================================================
    
    // Najpierw naprawa live
    fixLiveStream();
    
    // Uruchom AdGuard po krótkim opóźnieniu
    setTimeout(() => {
        try {
            runAdGuard();
        } catch(e) {
            console.log('AdGuard error:', e);
        }
    }, 100);
    
    // Uruchom blokowanie banerów sponsorowanych
    setTimeout(() => {
        try {
            blockSponsoredBanners();
        } catch(e) {
            console.log('Sponsored banners error:', e);
        }
    }, 200);
    
    // Okresowe czyszczenie dla live i banerów
    setInterval(() => {
        if (adblockEnabled) {
            fixLiveStream();
            
            // Usuń komunikaty o błędach
            document.querySelectorAll('.ytp-error-message, .ytp-error-content, .ytp-error, .ytp-error-screen').forEach(el => {
                el.style.display = 'none';
                el.style.opacity = '0';
                el.style.visibility = 'hidden';
            });
            
            // Spróbuj odtworzyć wideo live
            const video = document.querySelector('video');
            if (video && video.paused && video.src && video.src.includes('live')) {
                video.play().catch(() => {});
            }
        }
    }, 500);
    
})();
