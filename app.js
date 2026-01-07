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

        document.querySelectorAll('.example-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.domainInput.value = e.target.getAttribute('data-domain');
                this.checkSPF();
            });
        });

        this.domainInput.addEventListener('input', () => {
            if (this.resultsDiv.innerHTML) {
                this.resultsDiv.style.opacity = '0.5';
            }
        });

        this.domainInput.addEventListener('blur', () => {
            this.domainInput.value = this.domainInput.value.trim();
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.resultsDiv.innerHTML) {
                this.clearResults();
                this.domainInput.focus();
            }
        });
    }

    async checkSPF() {
        let domain = this.domainInput.value.trim().toLowerCase();
        this.domainInput.value = domain;

        if (!domain) {
            this.showError('Please enter a domain name');
            return;
        }

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
                    'This domain does not have an SPF record configured.'
                );
            } else {
                await this.displayResults(domain, spfRecords);
            }
        } catch (error) {
            this.showError(`Error checking SPF: ${error.message}`, 'Please verify the domain name is correct and try again.');
        } finally {
            this.checkButton.disabled = false;
        }
    }

    validateDomain(domain) {
        if (!domain) return false;
        const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        return domainRegex.test(domain);
    }

    async fetchSPFRecords(domain) {
        const response = await fetch(
            `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`,
            { headers: { 'Accept': 'application/dns-json' } }
        );

        if (!response.ok) throw new Error(`DNS lookup failed: ${response.statusText}`);
        const data = await response.json();
        if (data.Status !== 0) throw new Error('DNS query failed - domain may not exist');
        if (!data.Answer) return [];

        return data.Answer
            .filter(record => record.type === 16)
            .map(record => record.data.replace(/^"|"$/g, ''))
            .filter(record => record.startsWith('v=spf1'));
    }

    async fetchIncludedDomain(domain) {
        try {
            const records = await this.fetchSPFRecords(domain);
            return records.length > 0 ? records[0] : 'No SPF record found';
        } catch (error) {
            return `Error: ${error.message}`;
        }
    }

    async countDNSLookups(spfRecord, visited = new Set(), depth = 0) {
        if (depth > 10) return 0;

        let count = 0;
        const includeMatches = spfRecord.match(/include:([^\s]+)/g) || [];
        const includeDomains = includeMatches.map(m => m.replace('include:', ''));

        count += includeMatches.length;
        count += (spfRecord.match(/redirect=/g) || []).length;
        count += (spfRecord.match(/\ba\b/g) || []).length;
        count += (spfRecord.match(/\bmx\b/g) || []).length;
        count += (spfRecord.match(/\bptr\b/g) || []).length;
        count += (spfRecord.match(/exists:/g) || []).length;

        for (const domain of includeDomains) {
            if (visited.has(domain)) continue;
            visited.add(domain);

            try {
                const records = await this.fetchSPFRecords(domain);
                if (records.length > 0) {
                    const nestedCount = await this.countDNSLookups(records[0], visited, depth + 1);
                    count += nestedCount;
                }
            } catch (err) {}
        }

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

        highlighted = highlighted.replace(
            /include:([\S]+)/g, 
            (match, domain) => `<span class="mechanism include" data-domain="${domain}" title="${this.getMechanismExplanation('include:')}">include:${domain}<span class="mechanism-tooltip">${this.getMechanismExplanation('include:')}</span></span>`
        );

        highlighted = highlighted.replace(
            /redirect=([\S]+)/g, 
            (match, domain) => `<span class="mechanism redirect" data-domain="${domain}" title="${this.getMechanismExplanation('redirect=')}">redirect=${domain}<span class="mechanism-tooltip">${this.getMechanismExplanation('redirect=')}</span></span>`
        );

        highlighted = highlighted.replace(
            /ip([46]):([\S]+)/g, 
            (match, version, addr) => `<span class="mechanism ip" title="${this.getMechanismExplanation('ip' + version + ':')}">ip${version}:${addr}<span class="mechanism-tooltip">${this.getMechanismExplanation('ip' + version + ':')}</span></span>`
        );

        highlighted = highlighted.replace(
            /([~\-?+]?all)/g, 
            (match) => `<span class="mechanism all" title="${this.getMechanismExplanation(match)}">${match}<span class="mechanism-tooltip">${this.getMechanismExplanation(match)}</span></span>`
        );

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

        this.resultsDiv.innerHTML = `
            <div class="loading">
                <div class="spinner"></div>
                <p>Calculating DNS lookups...</p>
            </div>
        `;

        let totalDNSLookups = 0;
        try {
            totalDNSLookups = await this.countDNSLookups(spfRecords[0]);
        } catch (error) {
            console.error('DNS lookup calculation error:', error);
            totalDNSLookups = (spfRecords[0].match(/include:/g) || []).length;
        }

        const includesFound = this.extractIncludes(spfRecords[0]);
        const mechanisms = spfRecords[0].split(' ').length - 1;

        let html = `
            <div class="success">
                ✓ Found ${spfRecords.length} SPF record${spfRecords.length > 1 ? 's' : ''} for <strong>${domain}</strong>
            </div>
        `;

        // WARNING BOX - Shows if > 8 lookups
        if (totalDNSLookups > 8) {
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

        html += `
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">${spfRecords.length}</div>
                    <div class="stat-label">SPF Records</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${includesFound.length}</div>
                    <div class="stat-label">Includes/Redirects</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value ${totalDNSLookups > 8 ? 'warning' : ''}">${totalDNSLookups}</div>
                    <div class="stat-label">DNS Lookups ${totalDNSLookups > 8 ? '⚠️' : ''}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${mechanisms}</div>
                    <div class="stat-label">Total Mechanisms</div>
                </div>
            </div>
        `;

        html += `
            <div class="info-box">
                <strong>💡 Tips:</strong><br>
                • Click on blue (include:) or orange (redirect=) domains to see their SPF records<br>
                • Hover over mechanisms to see explanations<br>
                • Keep DNS lookups under 10 to avoid delivery issues<br>
                • Use the copy button to copy the SPF record
            </div>
            <button class="clear-btn" onclick="window.spfChecker.clearResults()">Clear Results</button>
        `;

        this.resultsDiv.innerHTML = html;
        this.attachIncludeHandlers();
        this.attachCopyHandlers();
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

                const existingItem = includesContent.querySelector(`[data-domain="${domain}"]`);
                if (existingItem) {
                    existingItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    return;
                }

                const loadingDiv = document.createElement('div');
                loadingDiv.className = 'include-item';
                loadingDiv.innerHTML = `
                    <span class="include-domain">${domain}</span>
                    <div class="include-loading">Loading SPF record...</div>
                `;

                const placeholder = includesContent.querySelector('.include-loading');
                if (placeholder && placeholder.textContent.includes('Click on')) {
                    includesContent.innerHTML = '';
                }

                includesContent.appendChild(loadingDiv);

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

document.addEventListener('DOMContentLoaded', () => {
    const checker = new SPFChecker();
    window.spfChecker = checker;
});