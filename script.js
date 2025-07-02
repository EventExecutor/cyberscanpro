class VirusTotalScanner {
    constructor() {
        this.apiKey = '';
        this.scanHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        this.initializeElements();
        this.attachEventListeners();
        this.loadApiKey();
        this.renderHistory();
    }

    initializeElements() {
        this.tabBtns = document.querySelectorAll('.tab-btn');
        this.tabContents = document.querySelectorAll('.tab-content');
        this.urlInput = document.getElementById('urlInput');
        this.scanUrlBtn = document.getElementById('scanUrlBtn');
        this.fileInput = document.getElementById('fileInput');
        this.fileDropZone = document.getElementById('fileDropZone');
        this.loadingSection = document.getElementById('loadingSection');
        this.resultsSection = document.getElementById('resultsSection');
        this.resultsContent = document.getElementById('resultsContent');
        this.newScanBtn = document.getElementById('newScanBtn');
        this.historySearch = document.getElementById('historySearch');
        this.historyFilter = document.getElementById('historyFilter');
        this.historyList = document.getElementById('historyList');
        this.apiStatus = document.getElementById('apiStatus');
        this.loadingText = document.getElementById('loadingText');
        this.toastContainer = document.getElementById('toastContainer');
        this.configApiBtn = document.getElementById('configApiBtn');
        this.apiModal = document.getElementById('apiModal');
        this.closeApiModal = document.getElementById('closeApiModal');
        this.apiKeyInput = document.getElementById('apiKeyInput');
        this.toggleApiKey = document.getElementById('toggleApiKey');
        this.rememberApiKey = document.getElementById('rememberApiKey');
        this.testApiBtn = document.getElementById('testApiBtn');
        this.saveApiBtn = document.getElementById('saveApiBtn');
    }

    attachEventListeners() {
        this.tabBtns.forEach(btn => btn.addEventListener('click', () => this.switchTab(btn.dataset.tab)));
        this.scanUrlBtn.addEventListener('click', () => this.scanUrl());
        this.urlInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') this.scanUrl(); });
        this.fileDropZone.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e.target.files[0]));
        this.fileDropZone.addEventListener('dragover', (e) => this.handleDragOver(e));
        this.fileDropZone.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        this.fileDropZone.addEventListener('drop', (e) => this.handleFileDrop(e));
        this.newScanBtn.addEventListener('click', () => this.resetScanner());
        this.historySearch.addEventListener('input', () => this.filterHistory());
        this.historyFilter.addEventListener('change', () => this.filterHistory());
        this.configApiBtn.addEventListener('click', () => this.showApiModal());
        this.closeApiModal.addEventListener('click', () => this.hideApiModal());
        this.apiModal.addEventListener('click', (e) => { if (e.target === this.apiModal) this.hideApiModal(); });
        this.toggleApiKey.addEventListener('click', () => this.togglePasswordVisibility());
        this.testApiBtn.addEventListener('click', () => this.testApiConnection());
        this.saveApiBtn.addEventListener('click', () => this.saveApiKey());
        this.apiKeyInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') this.saveApiKey(); });
    }

    async handleFileSelect(file) {
        if (!file) return;
        
        if (file.size > 32 * 1024 * 1024) { 
            this.showToast('File troppo grande (max 32MB per upload diretto)', 'error');
            return;
        }

        if (!this.apiKey) {
            this.showToast('Configura la tua API key prima di scansionare', 'error');
            this.showApiModal();
            return;
        }

        this.showLoading(`Caricamento file: ${file.name}...`);

        try {
            const analysisId = await this.submitFileScan(file);
            this.loadingText.textContent = 'Attendo risultati scansione...';
            
            const result = await this.pollForResults(analysisId, file.name, 'file');
            this.showResults(result);
            this.addToHistory(result);
        } catch (error) {
            console.error('Errore nella scansione del file:', error);
            this.showToast('Errore nella scansione: ' + error.message, 'error');
            this.hideLoading();
        }
    }

    async submitFileScan(file) {
        console.log('Invio file per scansione tramite proxy:', file.name);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('apiKey', this.apiKey);

        const response = await fetch('/.netlify/functions/virustotal-proxy', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        console.log('Risposta sottomissione file:', data);
        
        if (response.ok && data.data && data.data.id) {
            return data.data.id;
        } else {
            throw new Error(data.error?.message || 'Errore nella sottomissione file');
        }
    }

    async apiProxy(endpoint, options = {}, apiKey) {
        const body = {
            apiKey: apiKey,
            endpoint: endpoint,
            options: options
        };

        const response = await fetch('/.netlify/functions/virustotal-proxy', {
            method: 'POST',
            body: JSON.stringify(body),
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error?.message || `Errore del server proxy (status: ${response.status})`);
        }
        return data;
    }

    loadApiKey() {
        const savedApiKey = localStorage.getItem('virusTotalApiKey');
        if (savedApiKey) {
            this.apiKey = savedApiKey;
            this.updateApiStatus(true);
            this.showToast('API key caricata dal browser', 'success');
        } else {
            this.updateApiStatus(false);
            this.showToast('Configura la tua API key per iniziare', 'info');
        }
    }

    updateApiStatus(connected) {
        if (connected) {
            this.apiStatus.classList.add('connected');
            this.configApiBtn.innerHTML = '<i class="fas fa-key"></i> API Configurata';
        } else {
            this.apiStatus.classList.remove('connected');
            this.configApiBtn.innerHTML = '<i class="fas fa-key"></i> Configura API';
        }
    }

    showApiModal() {
        this.apiModal.classList.remove('hidden');
        this.apiKeyInput.value = this.apiKey;
        this.apiKeyInput.focus();
    }

    hideApiModal() {
        this.apiModal.classList.add('hidden');
    }

    togglePasswordVisibility() {
        const isPassword = this.apiKeyInput.type === 'password';
        this.apiKeyInput.type = isPassword ? 'text' : 'password';
        this.toggleApiKey.innerHTML = isPassword ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
    }

    async testApiConnection() {
        const apiKey = this.apiKeyInput.value.trim();
        if (!apiKey) {
            this.showToast('Inserisci una API key', 'warning');
            return;
        }
        this.testApiBtn.disabled = true;
        this.testApiBtn.innerHTML = '<i class="fas fa-spinner spin"></i> Testing...';
        try {
            await this.apiProxy(`users/${apiKey}`, { method: 'GET' }, apiKey);
            this.showToast('API key valida! Connessione riuscita', 'success');
        } catch (error) {
            this.showToast('API key non valida o errore: ' + error.message, 'error');
        } finally {
            this.testApiBtn.disabled = false;
            this.testApiBtn.innerHTML = '<i class="fas fa-vial"></i> Testa Connessione';
        }
    }

    saveApiKey() {
        const apiKey = this.apiKeyInput.value.trim();
        if (!apiKey) { this.showToast('Inserisci una API key', 'warning'); return; }
        this.apiKey = apiKey;
        if (this.rememberApiKey.checked) {
            localStorage.setItem('virusTotalApiKey', apiKey);
        } else {
            localStorage.removeItem('virusTotalApiKey');
        }
        this.updateApiStatus(true);
        this.hideApiModal();
        this.showToast('API key configurata con successo!', 'success');
    }

    switchTab(tab) {
        this.tabBtns.forEach(btn => btn.classList.remove('active'));
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
        this.tabContents.forEach(content => content.classList.remove('active'));
        document.getElementById(`${tab}-tab`).classList.add('active');
    }

    async scanUrl() {
        const url = this.urlInput.value.trim();
        if (!url || !this.isValidUrl(url)) {
            this.showToast('Inserisci un URL valido', 'warning');
            return;
        }
        if (!this.apiKey) {
            this.showToast('Configura la tua API key prima di scansionare', 'error');
            this.showApiModal();
            return;
        }
        this.showLoading('Invio URL per scansione...');
        try {
            const analysisId = await this.submitUrlScan(url);
            this.loadingText.textContent = 'Attendo risultati scansione...';
            const result = await this.pollForResults(analysisId, url, 'url');
            this.showResults(result);
            this.addToHistory(result);
        } catch (error) {
            console.error('Errore nella scansione:', error);
            this.showToast('Errore nella scansione: ' + error.message, 'error');
            this.hideLoading();
        }
    }

    async handleFileSelect(file) {
        this.showToast('La scansione dei file non è ancora supportata.', 'warning');
    }
    
    handleDragOver(e) { e.preventDefault(); this.fileDropZone.classList.add('drag-over'); }
    handleDragLeave(e) { e.preventDefault(); this.fileDropZone.classList.remove('drag-over'); }
    handleFileDrop(e) {
        e.preventDefault();
        this.fileDropZone.classList.remove('drag-over');
        if (e.dataTransfer.files[0]) this.handleFileSelect(e.dataTransfer.files[0]);
    }

    async submitUrlScan(url) {
        console.log('Invio URL per scansione tramite proxy:', url);
        const bodyContent = new URLSearchParams({ 'url': url }).toString();
        const data = await this.apiProxy('urls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: bodyContent
        }, this.apiKey);
        
        if (data.data && data.data.id) {
            return data.data.id;
        } else {
            throw new Error(data.error?.message || 'Errore nella sottomissione URL');
        }
    }

    async pollForResults(analysisId, originalResource, type, maxAttempts = 20) {
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            await this.sleep(15000);
            try {
                console.log(`Tentativo ${attempt + 1} di recupero risultati per:`, analysisId);
                const data = await this.apiProxy(`analyses/${analysisId}`, { method: 'GET' }, this.apiKey);
                if (data.data && data.data.attributes.status === 'completed') {
                    return this.formatScanResult(data.data, originalResource, type);
                }
                this.loadingText.textContent = `Scansione in corso... (tentativo ${attempt + 1}/${maxAttempts})`;
            } catch (error) {
                console.error(`Errore nel tentativo ${attempt + 1}:`, error);
                if (attempt === maxAttempts - 1) throw error;
            }
        }
        throw new Error('Timeout: la scansione sta richiedendo troppo tempo');
    }

    formatScanResult(data, resource, type) { const attributes = data.attributes; const stats = attributes.stats || {}; const positives = (stats.malicious || 0) + (stats.suspicious || 0); const total = Object.keys(attributes.results || {}).length; let status = 'clean'; if (positives > 0) { status = (stats.malicious || 0) > 0 ? 'infected' : 'suspicious'; } return { id: Date.now().toString(), resource, type, scanDate: attributes.date ? new Date(attributes.date * 1000).toISOString() : new Date().toISOString(), positives, total, permalink: `https://www.virustotal.com/gui/${type === 'url' ? 'url' : 'file'}/${data.meta.url_info.id}`, status, stats }; }
    showResults(result) { this.hideLoading(); this.resultsSection.classList.remove('hidden'); const statusClass = result.status; const statusText = { clean: 'Pulito', infected: 'Infetto', suspicious: 'Sospetto' }[result.status]; const detectionRate = result.total > 0 ? ((result.positives / result.total) * 100).toFixed(1) : 0; this.resultsContent.innerHTML = `<div class="result-card"><div class="result-header"><div class="result-info"><h3>${this.escapeHtml(result.resource)}</h3><p>Scansionato il ${new Date(result.scanDate).toLocaleString('it-IT')}</p></div><div class="status-badge ${statusClass}">${statusText}</div></div><div class="result-stats"><div class="stat-item"><div class="stat-value ${result.positives > 0 ? 'positive' : 'negative'}">${result.positives}</div><div class="stat-label">Rilevamenti</div></div><div class="stat-item"><div class="stat-value">${result.total}</div><div class="stat-label">Motori totali</div></div><div class="stat-item"><div class="stat-value ${result.positives > 0 ? 'positive' : 'negative'}">${detectionRate}%</div><div class="stat-label">Tasso rilevamento</div></div></div>${result.stats ? `<div class="detailed-stats"><h4>Dettagli Scansione:</h4><div class="stats-grid"><div class="stat-detail malicious"><span class="stat-number">${result.stats.malicious || 0}</span><span class="stat-name">Malevoli</span></div><div class="stat-detail suspicious"><span class="stat-number">${result.stats.suspicious || 0}</span><span class="stat-name">Sospetti</span></div><div class="stat-detail clean"><span class="stat-number">${result.stats.harmless || 0}</span><span class="stat-name">Puliti</span></div><div class="stat-detail undetected"><span class="stat-number">${result.stats.undetected || 0}</span><span class="stat-name">Non rilevati</span></div></div></div>` : ''}${result.permalink ? `<div style="margin-top: 20px;"><a href="${result.permalink}" target="_blank" class="secondary-btn"><i class="fas fa-external-link-alt"></i> Vedi report completo su VirusTotal</a></div>` : ''}</div>`; this.resultsContent.scrollIntoView({ behavior: 'smooth' }); }
    addToHistory(result) { this.scanHistory.unshift(result); if (this.scanHistory.length > 50) { this.scanHistory = this.scanHistory.slice(0, 50); } localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory)); this.renderHistory(); }
    renderHistory() { if (this.scanHistory.length === 0) { this.historyList.innerHTML = `<div class="no-history"><i class="fas fa-history"></i><p>Nessuna scansione effettuata</p></div>`; return; } const filteredHistory = this.getFilteredHistory(); if (filteredHistory.length === 0) { this.historyList.innerHTML = `<div class="no-history"><i class="fas fa-search"></i><p>Nessun risultato trovato</p></div>`; return; } this.historyList.innerHTML = filteredHistory.map(item => `<div class="history-item" onclick="scanner.showHistoryDetails('${item.id}')"><div class="history-info"><h4>${this.escapeHtml(item.resource)}</h4><p>${new Date(item.scanDate).toLocaleString('it-IT')} • ${item.positives}/${item.total} rilevamenti</p></div><div class="status-badge ${item.status}">${{clean: 'Pulito', infected: 'Infetto', suspicious: 'Sospetto'}[item.status]}</div></div>`).join(''); }
    getFilteredHistory() { let filtered = [...this.scanHistory]; const statusFilter = this.historyFilter.value; if (statusFilter !== 'all') { filtered = filtered.filter(item => item.status === statusFilter); } const searchTerm = this.historySearch.value.toLowerCase(); if (searchTerm) { filtered = filtered.filter(item => item.resource.toLowerCase().includes(searchTerm)); } return filtered; }
    filterHistory() { this.renderHistory(); }
    showHistoryDetails(id) { const item = this.scanHistory.find(scan => scan.id === id); if (item) { this.showResults(item); } }
    showLoading(message) { this.loadingText.textContent = message; this.loadingSection.classList.remove('hidden'); this.resultsSection.classList.add('hidden'); }
    hideLoading() { this.loadingSection.classList.add('hidden'); }
    resetScanner() { this.urlInput.value = ''; this.fileInput.value = ''; this.resultsSection.classList.add('hidden'); this.loadingSection.classList.add('hidden'); }
    showToast(message, type = 'info') { const toast = document.createElement('div'); toast.className = `toast ${type}`; const icon = { success: 'fas fa-check-circle', error: 'fas fa-exclamation-circle', warning: 'fas fa-exclamation-triangle', info: 'fas fa-info-circle' }[type]; toast.innerHTML = `<i class="${icon}"></i><span>${message}</span>`; this.toastContainer.appendChild(toast); setTimeout(() => { toast.remove(); }, 5000); }
    isValidUrl(string) { try { new URL(string); return true; } catch (_) { return false; } }
    escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
    sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
}

document.addEventListener('DOMContentLoaded', () => {
    window.scanner = new VirusTotalScanner();
});