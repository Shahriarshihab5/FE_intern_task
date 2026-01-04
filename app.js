class SPFChecker {
    constructor() {
        this.form = document.getElementById('spfForm');
        this.domainInput = document.getElementById('domainInput');
        this.checkButton = document.getElementById('checkButton');
        this.resultsDiv = document.getElementById('results');

        this.init();
    }

    init() {
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.checkSPF();
        });

        // Example domain buttons
        document.querySelectorAll('.example-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.domainInput.value = e.target.getAttribute('data-domain');
                this.checkSPF();
            });
        });

        // Clear results when input changes
        this.domainInput.addEventListener('input', () => {
            if (this.resultsDiv.innerHTML) {
                this.resultsDiv.style.opacity = '0.5';
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.resultsDiv.innerHTML) {
                this.clearResults();
                this.domainInput.focus();
            }
        });
    }

    async checkSPF() {
        const domain = this.domainInput.value.trim().toLowerCase();

        if (!this.validateDomain(domain)) {
            this.showError('Please enter a valid domain name', 'Domain must be in the format: example.com');
            return;
        }

        this.showLoading();
        this.checkButton.disabled = true;

        try {
            const spfRecords = await this.fetchSPFRecords(domain);

            if (spfRecords.length === 0) {
                this.showError(
                    `No SPF record found for ${domain}`,
                    'This domain does not have an SPF record configured. Email authentication may not be properly set up.'
                );
            } else {
                await this.displayResults(domain, spfRecords);
            }
        } catch (error) {
            this.showError(
                `Error checking SPF: ${error.message}`,
                'Please verify the domain name is correct and try again.'
            );
        } finally {
            this.checkButton.disabled = false;
        }
    }

    validateDomain(domain) {
        const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        return domainRegex.test(domain);
    }

    async fetchSPFRecords(domain) {
        // Using Google DNS over HTTPS API
        const response = await fetch(
            `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`,
            {
                headers: {
                    'Accept': 'application/dns-json'
                }
            }
        );

        if (!response.ok) {
            throw new Error(`DNS lookup failed: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.Status !== 0) {
            throw new Error('DNS query failed - domain may not exist');
        }

        if (!data.Answer) {
            return [];
        }

        // Filter for SPF records (TXT records starting with "v=spf1")
        const spfRecords = data.Answer
            .filter(record => record.type === 16) // TXT records
            .map(record => record.data.replace(/^"|"$/g, '')) // Remove quotes
            .filter(record => record.startsWith('v=spf1'));

        return spfRecords;
    }

    async fetchIncludedDomain(domain) {
        try {
            const records = await this.fetchSPFRecords(domain);
            return records.length > 0 ? records[0] : 'No SPF record found';
        } catch (error) {
            return `Error: ${error.message}`;
        }
    }

    calculateDNSLookups(spfRecord) {
        let count = 0;

        // Count include mechanisms
        count += (spfRecord.match(/include:/g) || []).length;

        // Count redirect mechanisms
        count += (spfRecord.match(/redirect=/g) || []).length;

        // Count a, mx, ptr, exists mechanisms (each requires DNS lookup)
        const mechanismMatches = spfRecord.match(/\b(a|mx|ptr|exists)(:|\s|$)/g) || [];
        count += mechanismMatches.length;

        return count;
    }

    getMechanismExplanation(mechanism) {
        const explanations = {
            'include:': 'Authorizes another domain\'s SPF record',
            'redirect=': 'Replaces this SPF record with another domain\'s',
            'ip4:': 'Authorizes an IPv4 address or range',
            'ip6:': 'Authorizes an IPv6 address or range',
            'a': 'Authorizes IP addresses from domain\'s A/AAAA records',
            'mx': 'Authorizes IP addresses from domain\'s MX records',
            'ptr': 'Authorizes if reverse DNS lookup matches (deprecated)',
            'exists': 'Performs a DNS A record lookup',
            '-all': 'Hard fail - rejects all other sources',
            '~all': 'Soft fail - marks as suspicious but accepts',
            '?all': 'Neutral - no policy statement',
            '+all': 'Pass - allows all (strongly discouraged!)',
        };
        return explanations[mechanism] || 'SPF mechanism';
    }

    highlightMechanisms(spfRecord) {
        let highlighted = spfRecord;

        // Highlight include: directives with tooltip
        highlighted = highlighted.replace(
            /include:([\S]+)/g, 
            (match, domain) => `<span class="mechanism include" data-domain="${domain}" title="${this.getMechanismExplanation('include:')}">include:${domain}<span class="mechanism-tooltip">${this.getMechanismExplanation('include:')}</span></span>`
        );

        // Highlight redirect= directives with tooltip
        highlighted = highlighted.replace(
            /redirect=([\S]+)/g, 
            (match, domain) => `<span class="mechanism redirect" data-domain="${domain}" title="${this.getMechanismExplanation('redirect=')}">redirect=${domain}<span class="mechanism-tooltip">${this.getMechanismExplanation('redirect=')}</span></span>`
        );

        // Highlight IP addresses with tooltip
        highlighted = highlighted.replace(
            /ip([46]):([\S]+)/g, 
            (match, version, addr) => `<span class="mechanism ip" title="${this.getMechanismExplanation('ip' + version + ':')}">ip${version}:${addr}<span class="mechanism-tooltip">${this.getMechanismExplanation('ip' + version + ':')}</span></span>`
        );

        // Highlight all mechanism with tooltip
        highlighted = highlighted.replace(
            /([~\-?+]?all)/g, 
            (match) => `<span class="mechanism all" title="${this.getMechanismExplanation(match)}">${match}<span class="mechanism-tooltip">${this.getMechanismExplanation(match)}</span></span>`
        );

        // Highlight other mechanisms
        highlighted = highlighted.replace(
            /\b(a|mx|ptr|exists)(:|\s|$)/g,
            (match, mech, suffix) => `<span class="mechanism ip" title="${this.getMechanismExplanation(mech)}">${mech}${suffix}<span class="mechanism-tooltip">${this.getMechanismExplanation(mech)}</span></span>`
        );

        return highlighted;
    }

    extractIncludes(spfRecord) {
        const includeRegex = /include:([\S]+)/g;
        const redirectRegex = /redirect=([\S]+)/g;

        const includes = [];
        let match;

        while ((match = includeRegex.exec(spfRecord)) !== null) {
            includes.push({ type: 'include', domain: match[1] });
        }

        while ((match = redirectRegex.exec(spfRecord)) !== null) {
            includes.push({ type: 'redirect', domain: match[1] });
        }

        return includes;
    }

    async displayResults(domain, spfRecords) {
        this.resultsDiv.style.opacity = '1';

        const includesFound = [];

        spfRecords.forEach(record => {
            const recordIncludes = this.extractIncludes(record);
            includesFound.push(...recordIncludes);
        });

        // Calculate total DNS lookups
        const totalDNSLookups = spfRecords.reduce((sum, record) => {
            return sum + this.calculateDNSLookups(record);
        }, 0);

        let html = `
            <div class="success">
                ✓ Found ${spfRecords.length} SPF record${spfRecords.length > 1 ? 's' : ''} for <strong>${domain}</strong>
            </div>
        `;

        // Warning for too many DNS lookups
        if (totalDNSLookups > 10) {
            html += `
                <div class="warning">
                    <strong>⚠️ Warning:</strong> This SPF record requires <strong>${totalDNSLookups} DNS lookups</strong>. 
                    RFC 7208 recommends keeping it under 10 to avoid email delivery issues. 
                    Consider consolidating or using SPF flattening.
                </div>
            `;
        }

        for (let i = 0; i < spfRecords.length; i++) {
            const record = spfRecords[i];
            const highlighted = this.highlightMechanisms(record);
            const includes = this.extractIncludes(record);
            const dnsLookups = this.calculateDNSLookups(record);

            html += `
                <div class="spf-record">
                    <h3>
                        SPF Record ${spfRecords.length > 1 ? i + 1 : ''}
                        <span class="badge">TXT</span>
                        <button class="copy-btn" data-record="${this.escapeHtml(record)}">📋 Copy</button>
                    </h3>
                    <div class="spf-content">${highlighted}</div>
                    ${includes.length > 0 ? `
                        <div class="expanded-includes" id="includes-${i}">
                            <h4>📋 Included/Redirected Domains (${includes.length})</h4>
                            <div id="includes-content-${i}">
                                <p class="include-loading">Click on highlighted domains above to expand...</p>
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Add statistics
        const totalIncludes = includesFound.length;
        const mechanisms = spfRecords[0].split(' ').length - 1;

        html += `
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">${spfRecords.length}</div>
                    <div class="stat-label">SPF Records</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${totalIncludes}</div>
                    <div class="stat-label">Includes/Redirects</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value ${totalDNSLookups > 10 ? 'warning' : ''}">${totalDNSLookups}</div>
                    <div class="stat-label">DNS Lookups ${totalDNSLookups > 10 ? '⚠️' : ''}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${mechanisms}</div>
                    <div class="stat-label">Total Mechanisms</div>
                </div>
            </div>
        `;

        // Add info box
        html += `
            <div class="info-box">
                <strong>💡 Tips:</strong><br>
                • Click on blue (include:) or orange (redirect=) domains to see their SPF records<br>
                • Hover over mechanisms to see explanations<br>
                • Keep DNS lookups under 10 to avoid delivery issues<br>
                • Use the copy button to copy the SPF record
            </div>
            <button class="clear-btn" onclick="document.querySelector('.spf-checker').clearResults()">Clear Results</button>
        `;

        this.resultsDiv.innerHTML = html;

        // Add click handlers for include/redirect mechanisms
        this.attachIncludeHandlers();

        // Add copy button handlers
        this.attachCopyHandlers();

        // Store reference for clear button
        document.querySelector('.spf-checker').clearResults = () => this.clearResults();
    }

    attachCopyHandlers() {
        document.querySelectorAll('.copy-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const record = e.target.getAttribute('data-record');

                navigator.clipboard.writeText(record).then(() => {
                    const originalText = e.target.innerHTML;
                    e.target.innerHTML = '✓ Copied!';
                    e.target.classList.add('copied');

                    setTimeout(() => {
                        e.target.innerHTML = originalText;
                        e.target.classList.remove('copied');
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    e.target.innerHTML = '❌ Failed';
                    setTimeout(() => {
                        e.target.innerHTML = '📋 Copy';
                    }, 2000);
                });
            });
        });
    }

    attachIncludeHandlers() {
        const mechanisms = document.querySelectorAll('.mechanism.include, .mechanism.redirect');

        mechanisms.forEach(mechanism => {
            mechanism.addEventListener('click', async (e) => {
                const domain = e.target.getAttribute('data-domain');
                const parentRecord = e.target.closest('.spf-record');
                const includesContent = parentRecord.querySelector('[id^="includes-content-"]');

                if (!includesContent) return;

                // Check if already loaded
                const existingItem = includesContent.querySelector(`[data-domain="${domain}"]`);
                if (existingItem) {
                    existingItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    return;
                }

                // Add loading state
                const loadingDiv = document.createElement('div');
                loadingDiv.className = 'include-item';
                loadingDiv.innerHTML = `
                    <span class="include-domain">${domain}</span>
                    <div class="include-loading">Loading SPF record...</div>
                `;

                // Remove placeholder text if exists
                const placeholder = includesContent.querySelector('.include-loading');
                if (placeholder && placeholder.textContent.includes('Click on')) {
                    includesContent.innerHTML = '';
                }

                includesContent.appendChild(loadingDiv);

                // Fetch the included domain's SPF record
                const spfRecord = await this.fetchIncludedDomain(domain);

                loadingDiv.setAttribute('data-domain', domain);
                loadingDiv.innerHTML = `
                    <span class="include-domain">${domain}</span>
                    <div>${this.highlightMechanisms(spfRecord)}</div>
                `;

                loadingDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            });
        });
    }

    showLoading() {
        this.resultsDiv.innerHTML = `
            <div class="loading">
                <div class="spinner"></div>
                <p>Checking SPF records...</p>
            </div>
        `;
    }

    showError(message, details = null) {
        this.resultsDiv.innerHTML = `
            <div class="error">
                <strong>⚠️ Error:</strong> ${message}
                ${details ? `<div style="margin-top: 10px; font-size: 0.9rem; opacity: 0.9;">${details}</div>` : ''}
            </div>
        `;
    }

    clearResults() {
        this.resultsDiv.innerHTML = '';
        this.domainInput.value = '';
        this.domainInput.focus();
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
}

// Initialize the app
document.addEventListener('DOMContentLoaded', () => {
    const checker = new SPFChecker();
    // Store reference globally for clear button
    document.querySelector('.container').classList.add('spf-checker');
    window.spfChecker = checker;
});