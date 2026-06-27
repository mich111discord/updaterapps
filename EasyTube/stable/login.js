// =====================================================
// FUNKCJA LOGOWANIA - NIEBIESKI PRZYCISK
// =====================================================

function setupLoginButton() {
    try {
        if (!document) return;
        
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
                    'ytd-masthead #buttons a[href*="accounts.google.com"], ' +
                    'ytd-button-renderer[button-next] a, ' +
                    '#buttons ytd-button-renderer a'
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
                            
                            // Ustaw styl niebieskiego przycisku
                            btn.style.color = '#1E90FF';
                            btn.style.fontWeight = 'bold';
                            
                            // Dodaj obsługę kliknięcia
                            btn.addEventListener('click', function(e) {
                                const currentSessionCheck = document.cookie.includes("SID=") || document.cookie.includes("HSID=");
                                if (!currentSessionCheck) {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    alert("Aby się zalogować, użyj niebieskiego przycisku 'ZALOGUJ SIĘ ▼' na górnym pasku aplikacji EasyTube!");
                                }
                            }, true);
                        }
                    }
                });
            } catch(e) {}
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
        
    } catch(e) {}
}

// Uruchom funkcję
setupLoginButton();
