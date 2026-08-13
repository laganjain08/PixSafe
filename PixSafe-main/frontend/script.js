document.addEventListener("DOMContentLoaded", () => {

    const API_BASE = "https://pixsafe.onrender.com";
    // =========================
    // 🔄 PANEL FUNCTIONS
    // =========================
    window.scrollToFeatures = function () {
        document.getElementById('featuresSection').scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    };
    window.openPanel = function (id) {
        if (id === 'featurePanel') {
            const dd = document.getElementById('featuresDropdown');
            dd.classList.toggle('open');

            // close when clicking outside
            const close = (e) => {
                if (!dd.contains(e.target) && !e.target.closest('.nav-links')) {
                    dd.classList.remove('open');
                    document.removeEventListener('click', close);
                }
            };
            setTimeout(() => document.addEventListener('click', close), 0);
            return;
        }
        document.getElementById(id).classList.add("active");
    };

    window.closePanel = function () {
        document.querySelectorAll(".slide-panel").forEach(p => {
            p.classList.remove("active");
        });
    };

    // =========================
    // 📁 FILE UPLOAD
    // =========================
    const fileInput = document.getElementById("fileInput");

    if (fileInput) {
        fileInput.addEventListener("change", async () => {
            const file = fileInput.files[0];
            if (!file) return;

            document.getElementById("fileText").innerText = file.name;
            showLoader(true);

            const formData = new FormData();
            formData.append("file", file);

            const res = await fetch(`${API_BASE}/api/scan-image`, {
                method: "POST",
                body: formData
            });

            const data = await res.json();
            showLoader(false);

            showResult(data.message);
        });
    }

    // =========================
    // 🌐 URL SCAN
    // =========================
    window.scanURL = async function () {
        const url = document.getElementById("urlInput").value;

        showLoader(true);

        const res = await fetch(`${API_BASE}/api/scan-url`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await res.json();
        showLoader(false);

        showResult(data.message);
    };

    // =========================
    // ⏳ LOADER
    // =========================
    function showLoader(show) {
        const loader = document.getElementById("loader");
        if (loader) {
            loader.classList.toggle("hidden", !show);
        }
    }

    // =========================
    // 📊 RESULT
    // =========================
    function showResult(msg) {
        const result = document.getElementById("result");
        if (result) {
            result.innerText = msg;
        }
    }

    // =========================
    // 🎯 SLIDER (FIXED)
    // =========================
    let currentSlide = 0;

    const slides = document.querySelectorAll(".slide");
    const dots = document.querySelectorAll(".dots span");
    const progressBar = document.querySelector(".top-line");

    let interval;

    function showSlide(index) {
        slides.forEach((slide, i) => {
            slide.classList.remove("active");
            if (dots[i]) dots[i].classList.remove("active");
        });

        slides[index].classList.add("active");
        if (dots[index]) dots[index].classList.add("active");

        // 🔥 Restart progress animation (safe check)
        if (progressBar) {
            progressBar.classList.remove("animate");
            void progressBar.offsetWidth;
            progressBar.classList.add("animate");
        }
    }

    // DOT CLICK
    window.goToSlide = function (index) {
        currentSlide = index;
        showSlide(currentSlide);

        clearInterval(interval);
        startAutoSlide();
    };

    // AUTO SLIDE
    function startAutoSlide() {
        interval = setInterval(() => {
            currentSlide = (currentSlide + 1) % slides.length;
            showSlide(currentSlide);
        }, 3000);
    }

    // INIT
    if (slides.length > 0) {
        showSlide(currentSlide);
        startAutoSlide();
    }

});