/**
 * NexaVault Client Application Script
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Auto-dismiss alerts after 6 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-8px)';
            setTimeout(() => alert.remove(), 400);
        }, 6000);
    });

    // 2. Animated Numerical Counters
    const counters = document.querySelectorAll('.counter-value');
    counters.forEach(counter => {
        const target = +counter.getAttribute('data-target') || +counter.innerText;
        if (isNaN(target)) return;
        
        let current = 0;
        const increment = target / 30;
        const updateCounter = () => {
            current += increment;
            if (current < target) {
                counter.innerText = Math.ceil(current);
                requestAnimationFrame(updateCounter);
            } else {
                counter.innerText = target;
            }
        };
        updateCounter();
    });

    // 3. Quick Demo Login Helper
    window.selectDemoRole = function(email, password) {
        const emailInput = document.getElementById('login-email');
        const passInput = document.getElementById('login-password');
        if (emailInput && passInput) {
            emailInput.value = email;
            passInput.value = password;
            // Highlight inputs briefly
            emailInput.style.borderColor = '#E85A4F';
            passInput.style.borderColor = '#E85A4F';
            setTimeout(() => {
                emailInput.style.borderColor = '';
                passInput.style.borderColor = '';
            }, 600);
        }
    };
});
