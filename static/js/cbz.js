"use strict";

(function() {
    const FILE_ID = window.__CBZ_CONFIG.fileId;
    let totalPages = 0;
    let currentPage = window.__CBZ_CONFIG.initialPage || 0; // 0-indexed, loaded from saved preferences

    const img = document.getElementById('cbzImage');
    const pageInput = document.getElementById('pageInput');
    const pageTotal = document.getElementById('pageTotal');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const loading = document.getElementById('loadingIndicator');
    const clickLeft = document.getElementById('clickLeft');
    const clickRight = document.getElementById('clickRight');

    function showPage(page) {
        if (page < 0 || page >= totalPages) return;
        currentPage = page;

        // Show loading indicator
        img.style.display = 'none';
        loading.style.display = 'block';

        // Load image from server
        const imgSrc = `/api/cbz/${FILE_ID}/image?page=${page}`;
        img.onload = function() {
            loading.style.display = 'none';
            img.style.display = 'block';
        };
        img.onerror = function() {
            loading.innerHTML = '<p class="text-danger small mb-0">Failed to load page</p>';
        };
        img.src = imgSrc;

        // Update UI
        pageInput.value = page + 1; // 1-indexed for display
        pageInput.max = totalPages;
        prevBtn.disabled = page === 0;
        nextBtn.disabled = page === totalPages - 1;

        // Save position (debounced)
        savePosition(page);
    }

    let saveTimeout = null;
    function savePosition(page) {
        if (saveTimeout) clearTimeout(saveTimeout);
        saveTimeout = setTimeout(() => {
            fetch(`/api/cbz/${FILE_ID}/prefs`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ page: page })
            }).catch(() => {});
        }, 300);
    }

    function goToPage(page) {
        if (page < 0) page = 0;
        if (page >= totalPages) page = totalPages - 1;
        showPage(page);
    }

    // Event listeners
    prevBtn.addEventListener('click', () => goToPage(currentPage - 1));
    nextBtn.addEventListener('click', () => goToPage(currentPage + 1));

    clickLeft.addEventListener('click', () => goToPage(currentPage - 1));
    clickRight.addEventListener('click', () => goToPage(currentPage + 1));

    pageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const val = parseInt(pageInput.value);
            if (!isNaN(val) && val >= 1 && val <= totalPages) {
                goToPage(val - 1); // Convert to 0-indexed
            } else {
                pageInput.value = currentPage + 1; // Reset to current
            }
        }
    });

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        if (e.target === pageInput) return; // Don't navigate when typing
        if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            e.preventDefault();
            goToPage(currentPage - 1);
        } else if (e.key === 'ArrowRight' || e.key === 'ArrowDown' || e.key === ' ') {
            e.preventDefault();
            goToPage(currentPage + 1);
        } else if (e.key === 'Home') {
            e.preventDefault();
            goToPage(0);
        } else if (e.key === 'End') {
            e.preventDefault();
            goToPage(totalPages - 1);
        }
    });

    // Touch swipe support
    let touchStartX = 0;
    const imageArea = document.getElementById('imageArea');
    imageArea.addEventListener('touchstart', (e) => {
        touchStartX = e.changedTouches[0].screenX;
    }, { passive: true });
    imageArea.addEventListener('touchend', (e) => {
        const dx = e.changedTouches[0].screenX - touchStartX;
        if (Math.abs(dx) > 50) {
            if (dx > 0) goToPage(currentPage - 1);
            else goToPage(currentPage + 1);
        }
    }, { passive: true });

    // Load page count first, then show initial page
    fetch(`/api/cbz/${FILE_ID}/pages`)
        .then(r => r.json())
        .then(data => {
            totalPages = data.pages || 0;
            pageTotal.textContent = '/' + totalPages;
            pageInput.max = totalPages;

            if (totalPages === 0) {
                loading.innerHTML = '<p class="text-secondary small mb-0">No pages found in CBZ file</p>';
                return;
            }

            // Clamp saved page
            if (currentPage < 0) currentPage = 0;
            if (currentPage >= totalPages) currentPage = totalPages - 1;

            showPage(currentPage);
        })
        .catch(() => {
            loading.innerHTML = '<p class="text-danger small mb-0">Failed to load CBZ file</p>';
        });
})();
