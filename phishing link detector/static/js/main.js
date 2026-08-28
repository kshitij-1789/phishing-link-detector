document.getElementById('analyzerForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const urlInput = document.getElementById('urlInput').value.trim();
    const submitBtn = document.getElementById('submitBtn');
    const loadingState = document.getElementById('loadingState');
    const resultsDashboard = document.getElementById('resultsDashboard');
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');

    // Reset layout UI elements
    errorMessage.classList.add('hidden');
    resultsDashboard.classList.add('hidden');
    
    // UI Validation checks
    if (!urlInput.startsWith('http://') && !urlInput.startsWith('https://')) {
        errorText.innerText = "Invalid format: Target URL must begin with http:// or https://";
        errorMessage.classList.remove('hidden');
        return;
    }

    // Toggle scanning animation loop states
    submitBtn.disabled = true;
    loadingState.classList.remove('hidden');

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: urlInput })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "An unexpected core system failure occurred.");
        }

        // --- Render UI Dashboard Data Views ---
        document.getElementById('analyzedUrl').innerText = data.url;
        
        // Render Core Verdict metrics
        const verdictText = document.getElementById('verdictText');
        const verdictBadge = document.getElementById('verdictBadge');
        verdictText.innerText = data.verdict;
        verdictText.style.color = data.verdict_color;
        verdictBadge.style.backgroundColor = data.verdict_color;

        // Render Global Score metrics & Animate Progress Gauge
        document.getElementById('riskScoreDisplay').innerText = data.risk_score;
        const riskBar = document.getElementById('riskBarWidth');
        riskBar.style.width = `${data.risk_score}%`;
        riskBar.style.backgroundColor = data.verdict_color;

        // Render VirusTotal Metrics Details
        document.getElementById('vtMalicious').innerText = data.malicious_count;
        document.getElementById('vtSuspicious').innerText = data.suspicious_count;
        document.getElementById('vtHarmless').innerText = data.harmless_count;

        // Build heuristic factors list items
        const reasonsList = document.getElementById('reasonsList');
        reasonsList.innerHTML = ''; // clear current elements
        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.className = "flex items-start gap-2.5 line-clamp-2 text-gray-300";
            li.innerHTML = `<i class="fa-solid fa-circle-chevron-right text-cyan-500/80 mt-1 text-xs"></i> <span>${reason}</span>`;
            reasonsList.appendChild(li);
        });

        // Build Action Items Guidelines list
        const recommendationsList = document.getElementById('recommendationsList');
        recommendationsList.innerHTML = ''; // clear current elements
        data.recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.className = "flex items-start gap-2.5 text-gray-300";
            li.innerHTML = `<i class="fa-solid fa-shield text-emerald-500/80 mt-1 text-xs"></i> <span>${rec}</span>`;
            recommendationsList.appendChild(li);
        });

        // Display Completed Data Dashboard
        resultsDashboard.classList.remove('hidden');

    } catch (err) {
        errorText.innerText = err.message;
        errorMessage.classList.remove('hidden');
    } finally {
        // Kill loaders
        submitBtn.disabled = false;
        loadingState.classList.add('hidden');
    }
});