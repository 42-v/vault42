// Vault Admin Gateway — client-side JavaScript
// No frameworks, no dependencies. Vanilla JS only.
// CSP-compliant: no inline handlers — all event binding via addEventListener.

(function() {
    'use strict';

    // ========== Token Management ==========

    let token = sessionStorage.getItem('admin_token') || '';

    function api(method, path, body) {
        const opts = {
            method: method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (token) opts.headers['Authorization'] = 'Bearer ' + token;
        if (body) opts.body = JSON.stringify(body);
        return fetch(path, opts).then(function(r) {
            if (r.status === 401) {
                sessionStorage.removeItem('admin_token');
                window.location.href = '/admin/login?expired=1';
                return Promise.reject(new Error('session_expired'));
            }
            return r.json();
        });
    }

    // ========== Utilities ==========

    function el(id, val) {
        const e = document.getElementById(id);
        if (e) {
            e.textContent = val;
            e.classList.remove('skeleton');
        }
    }

    function appendCell(tr, text, colspan) {
        const td = document.createElement('td');
        td.textContent = text || '';
        if (colspan) td.colSpan = colspan;
        tr.appendChild(td);
        return td;
    }

    function fmtTime(s) {
        if (!s) return '\u2014';
        try { return new Date(s).toLocaleString(); }
        catch { return String(s); }
    }

    function timeAgo(s) {
        if (!s) return '\u2014';
        try {
            const now = Date.now();
            const then = new Date(s).getTime();
            const diff = Math.floor((now - then) / 1000);
            if (diff < 60) return 'just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            if (diff < 172800) return 'yesterday';
            return Math.floor(diff / 86400) + 'd ago';
        } catch { return fmtTime(s); }
    }

    function setResultCount(id, count) {
        const span = document.getElementById(id);
        if (span) span.textContent = count === 1 ? '1 result' : count + ' results';
    }

    // ========== Toast Notifications ==========

    const MAX_TOASTS = 3;

    function showToast(message, type) {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        // Limit visible toasts.
        let existing = container.querySelectorAll('.toast');
        while (existing.length >= MAX_TOASTS) {
            existing[existing.length - 1].remove();
            existing = container.querySelectorAll('.toast');
        }
        const toast = document.createElement('div');
        toast.className = 'toast toast-' + (type || 'info');
        toast.textContent = message;
        toast.setAttribute('role', 'status');
        container.appendChild(toast);
        void toast.offsetHeight; // force reflow before adding the visible class
        toast.classList.add('toast-visible');
        setTimeout(function() {
            toast.classList.remove('toast-visible');
            setTimeout(function() { toast.remove(); }, 300);
        }, 4000);
    }

    // ========== Confirmation Modal ==========

    let _modalTrigger = null;

    function confirmModal(message) {
        _modalTrigger = document.activeElement;
        return new Promise(function(resolve) {
            const overlay = document.getElementById('modalOverlay');
            const title = document.getElementById('modalTitle');
            const body = document.getElementById('modalBody');
            const btnCancel = document.getElementById('modalCancel');
            const btnConfirm = document.getElementById('modalConfirm');
            if (!overlay) { resolve(confirm(message)); return; }

            title.textContent = 'Confirm';
            body.textContent = message;
            overlay.style.display = 'flex';
            // Trigger animation.
            requestAnimationFrame(function() {
                overlay.classList.add('modal-visible');
            });
            btnConfirm.focus();

            function cleanup() {
                overlay.classList.remove('modal-visible');
                overlay.style.display = 'none';
                btnCancel.removeEventListener('click', onCancel);
                btnConfirm.removeEventListener('click', onConfirm);
                overlay.removeEventListener('keydown', onKeydown);
                if (_modalTrigger && _modalTrigger.focus) _modalTrigger.focus();
                _modalTrigger = null;
            }
            function onCancel() { cleanup(); resolve(false); }
            function onConfirm() { cleanup(); resolve(true); }
            function onKeydown(e) {
                if (e.key === 'Escape') { e.stopPropagation(); onCancel(); return; }
                // Focus trap: Tab cycles between Cancel and Confirm.
                if (e.key === 'Tab') {
                    const focusable = [btnCancel, btnConfirm];
                    const first = focusable[0], last = focusable[focusable.length - 1];
                    if (e.shiftKey) {
                        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
                    } else {
                        if (document.activeElement === last) { e.preventDefault(); first.focus(); }
                    }
                }
            }
            btnCancel.addEventListener('click', onCancel);
            btnConfirm.addEventListener('click', onConfirm);
            overlay.addEventListener('keydown', onKeydown);
        });
    }

    // ========== Loading States ==========

    function setLoading(btn, loading) {
        if (!btn) return;
        btn.disabled = loading;
        if (loading) {
            btn.dataset.originalText = btn.textContent;
            btn.textContent = 'Loading...';
            btn.classList.add('btn-loading');
        } else {
            btn.textContent = btn.dataset.originalText || btn.textContent;
            btn.classList.remove('btn-loading');
            delete btn.dataset.originalText;
        }
    }

    // ========== Copy to Clipboard ==========

    function copyToClipboard(text, btn) {
        navigator.clipboard.writeText(text).then(function() {
            if (btn) {
                const orig = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(function() { btn.textContent = orig; }, 1500);
            }
            showToast('Copied to clipboard', 'success');
        }).catch(function() {
            showToast('Copy failed', 'error');
        });
    }

    // ========== Table Sorting ==========

    // Per-page data caches for sorting.
    const _tableData = {};

    function sortData(dataKey, field, direction) {
        const data = _tableData[dataKey];
        if (!data) return [];
        return data.slice().sort(function(a, b) {
            let va = a[field], vb = b[field];
            if (va == null) va = '';
            if (vb == null) vb = '';
            // Numeric comparison for numbers.
            if (typeof va === 'number' && typeof vb === 'number') {
                return direction === 'asc' ? va - vb : vb - va;
            }
            // Boolean comparison.
            if (typeof va === 'boolean') va = va ? 1 : 0;
            if (typeof vb === 'boolean') vb = vb ? 1 : 0;
            if (typeof va === 'number' && typeof vb === 'number') {
                return direction === 'asc' ? va - vb : vb - va;
            }
            // String comparison.
            va = String(va).toLowerCase();
            vb = String(vb).toLowerCase();
            if (va < vb) return direction === 'asc' ? -1 : 1;
            if (va > vb) return direction === 'asc' ? 1 : -1;
            return 0;
        });
    }

    // Track sort state per table: { field, direction }.
    const _sortState = {};

    function initSortableHeaders() {
        document.addEventListener('click', function(e) {
            const th = e.target.closest('th[data-sort]');
            if (!th) return;
            const table = th.closest('table');
            if (!table) return;
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            const dataKey = tbody.id;
            if (!dataKey || !_tableData[dataKey]) return;

            const field = th.getAttribute('data-sort');
            const state = _sortState[dataKey] || {};
            const direction = (state.field === field && state.direction === 'asc') ? 'desc' : 'asc';
            _sortState[dataKey] = { field: field, direction: direction };

            // Update header classes.
            const allTh = table.querySelectorAll('th[data-sort]');
            for (let i = 0; i < allTh.length; i++) {
                allTh[i].classList.remove('sort-asc', 'sort-desc');
            }
            th.classList.add('sort-' + direction);

            // Sort and re-render.
            const sorted = sortData(dataKey, field, direction);
            const renderers = {
                'keysBody': renderKeysRows,
                'sessionsBody': renderSessionsRows,
                'clientsBody': renderClientsRows,
                'adminsBody': renderAdminsRows,
                'configBody': renderConfigRows,
                'auditBody': function(data) { renderAuditTable('auditBody', data, document.body.dataset.page === 'dashboard'); },
                'usersBody': renderUsersRows
            };
            if (renderers[dataKey]) renderers[dataKey](sorted);
        });
    }

    // ========== Audit Table Renderer ==========

    function renderAuditTable(id, entries, useTimeAgo) {
        const tbody = document.getElementById(id);
        if (!tbody) return;
        _tableData[id] = entries || [];
        tbody.innerHTML = '';
        if (!entries || entries.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'empty-state';
            td.textContent = 'No audit events found';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        entries.forEach(function(e) {
            const tr = document.createElement('tr');
            appendCell(tr, useTimeAgo ? timeAgo(e.timestamp) : fmtTime(e.timestamp));
            // Event type badge
            const eventTd = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = 'badge';
            badge.textContent = e.event_type;
            eventTd.appendChild(badge);
            tr.appendChild(eventTd);
            appendCell(tr, e.user_id ? e.user_id.substring(0, 8) : '\u2014');
            appendCell(tr, e.ip || '\u2014');
            // Risk score
            const riskTd = document.createElement('td');
            const risk = e.risk_score || 0;
            const riskSpan = document.createElement('span');
            riskSpan.className = risk >= 5 ? 'status-inactive' : risk > 0 ? 'status-locked' : 'status-active';
            riskSpan.textContent = String(risk);
            riskTd.appendChild(riskSpan);
            tr.appendChild(riskTd);
            const metaTd = document.createElement('td');
            const code = document.createElement('code');
            code.textContent = JSON.stringify(e.metadata || {}).substring(0, 80);
            metaTd.appendChild(code);
            tr.appendChild(metaTd);
            tbody.appendChild(tr);
        });
    }

    // ========== Page: Login ==========

    function initLogin() {
        const form = document.getElementById('loginForm');
        if (!form) return;

        // Show expired message
        if (window.location.search.indexOf('expired=1') !== -1) {
            const errEl = document.getElementById('loginError');
            if (errEl) {
                errEl.textContent = 'Session expired. Please sign in again.';
                errEl.style.display = 'block';
            }
        }

        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const btn = form.querySelector('button[type="submit"]');
            setLoading(btn, true);
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const totpCode = document.getElementById('totp_code').value;
            const errEl = document.getElementById('loginError');

            api('POST', '/admin/auth/login', {
                username: username,
                password: password,
                totp_code: totpCode
            }).then(function(data) {
                setLoading(btn, false);
                if (data && data.error) {
                    errEl.textContent = data.error === 'invalid_credentials' ? 'Invalid credentials' : data.error;
                    errEl.style.display = 'block';
                    return;
                }
                if (data && data.token) {
                    token = data.token;
                    sessionStorage.setItem('admin_token', token);
                    // Redirect to TOTP setup if 2FA not configured
                    if (data.requires_2fa) {
                        window.location.href = '/admin/ui/totp-setup';
                    } else {
                        window.location.href = '/admin/';
                    }
                }
            }).catch(function() { setLoading(btn, false); });
        });
    }

    // ========== Page: Dashboard ==========

    function loadDashboard() {
        api('GET', '/admin/keys').then(function(d) {
            if (d && d.keys) el('keyCount', d.keys.length);
        }).catch(function(){});
        api('GET', '/admin/sessions').then(function(d) {
            if (d && d.sessions) el('sessionCount', d.sessions.length);
        }).catch(function(){});
        api('GET', '/admin/admins').then(function(d) {
            if (d && d.admins) el('adminCount', d.admins.length);
        }).catch(function(){});
        api('GET', '/admin/clients').then(function(d) {
            if (d && d.clients) el('clientCount', d.clients.length);
        }).catch(function(){});
        api('GET', '/admin/audit?limit=10').then(function(d) {
            if (d && d.entries) renderAuditTable('auditBody', d.entries, true);
        }).catch(function(){});
    }

    function initDashboard() {
        loadDashboard();
        setInterval(function() {
            if (!document.hidden) loadDashboard();
        }, 30000);
    }

    // ========== Page: Keys ==========

    function renderKeysRows(keys) {
        const tbody = document.getElementById('keysBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (keys.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'empty-state';
            td.textContent = 'No signing keys found';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        keys.forEach(function(k) {
            const tr = document.createElement('tr');
            // KID with copy
            const kidTd = document.createElement('td');
            const kidCode = document.createElement('code');
            kidCode.textContent = k.kid;
            kidCode.id = 'kid-' + k.kid;
            kidTd.appendChild(kidCode);
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn btn-sm copy-btn';
            copyBtn.textContent = 'Copy';
            copyBtn.setAttribute('data-action', 'copy');
            copyBtn.setAttribute('data-copy-target', 'kid-' + k.kid);
            copyBtn.setAttribute('aria-label', 'Copy key ID');
            kidTd.appendChild(copyBtn);
            tr.appendChild(kidTd);
            appendCell(tr, k.algorithm || 'RS256');
            // Status badge
            const statusTd = document.createElement('td');
            const badge = document.createElement('span');
            const status = k.status || 'active';
            badge.className = 'badge badge-' + status;
            badge.textContent = status;
            statusTd.appendChild(badge);
            tr.appendChild(statusTd);
            appendCell(tr, timeAgo(k.created_at));
            appendCell(tr, k.retired_at ? timeAgo(k.retired_at) : '\u2014');
            const td = document.createElement('td');
            if (status === 'active') {
                const btn = document.createElement('button');
                btn.className = 'btn btn-sm btn-danger';
                btn.textContent = 'Revoke';
                btn.setAttribute('data-action', 'revoke-key');
                btn.setAttribute('data-id', k.kid);
                btn.setAttribute('aria-label', 'Revoke key ' + k.kid);
                td.appendChild(btn);
            }
            tr.appendChild(td);
            tbody.appendChild(tr);
        });
    }

    function refreshKeys() {
        api('GET', '/admin/keys').then(function(d) {
            if (!d || !d.keys) return;
            _tableData['keysBody'] = d.keys;
            renderKeysRows(d.keys);
        }).catch(function(){});
    }

    function initKeys() {
        refreshKeys();
        setInterval(function() {
            if (!document.hidden) refreshKeys();
        }, 60000);
    }

    // ========== Page: Sessions ==========


    function renderSessionsRows(sessions) {
        const tbody = document.getElementById('sessionsBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (sessions.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 5;
            td.className = 'empty-state';
            td.textContent = 'No active sessions';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        sessions.forEach(function(s) {
            const tr = document.createElement('tr');
            appendCell(tr, s.id.substring(0, 8));
            appendCell(tr, s.admin_id.substring(0, 8));
            appendCell(tr, s.ip);
            appendCell(tr, timeAgo(s.created_at));
            appendCell(tr, fmtTime(s.expires_at));
            tbody.appendChild(tr);
        });
    }

    function refreshSessions() {
        api('GET', '/admin/sessions').then(function(d) {
            if (!d || !d.sessions) return;
            _tableData['sessionsBody'] = d.sessions;
            renderSessionsRows(d.sessions);
        }).catch(function(){});
    }

    function initSessions() {
        refreshSessions();
        setInterval(function() {
            if (!document.hidden) refreshSessions();
        }, 60000);
    }

    // ========== Page: Users ==========

    function renderUsersRows(users) {
        const tbody = document.getElementById('usersBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (users.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 7;
            td.className = 'empty-state';
            td.textContent = 'No users found';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        users.forEach(function(u) {
            const tr = document.createElement('tr');
            // ID with link
            const idTd = document.createElement('td');
            const idLink = document.createElement('a');
            idLink.href = '/admin/ui/users/' + u.id;
            idLink.textContent = u.id.substring(0, 8);
            idLink.className = 'accent';
            idTd.appendChild(idLink);
            tr.appendChild(idTd);
            appendCell(tr, u.email);
            appendCell(tr, u.email_verified ? 'Yes' : 'No');
            appendCell(tr, u.mfa_required ? 'Yes' : 'No');
            // Locked status
            const lockedTd = document.createElement('td');
            if (u.locked_until) {
                const span = document.createElement('span');
                span.className = 'badge badge-locked';
                span.textContent = 'Locked';
                lockedTd.appendChild(span);
            } else {
                const span2 = document.createElement('span');
                span2.className = 'status-active';
                span2.textContent = 'No';
                lockedTd.appendChild(span2);
            }
            tr.appendChild(lockedTd);
            appendCell(tr, timeAgo(u.created_at));
            // Action buttons
            const td = document.createElement('td');
            const lockBtn = document.createElement('button');
            lockBtn.className = 'btn btn-sm';
            lockBtn.textContent = 'Lock';
            lockBtn.setAttribute('data-action', 'lock-user');
            lockBtn.setAttribute('data-id', u.id);
            lockBtn.setAttribute('aria-label', 'Lock user ' + u.email);
            td.appendChild(lockBtn);
            td.appendChild(document.createTextNode(' '));
            const unlockBtn = document.createElement('button');
            unlockBtn.className = 'btn btn-sm';
            unlockBtn.textContent = 'Unlock';
            unlockBtn.setAttribute('data-action', 'unlock-user');
            unlockBtn.setAttribute('data-id', u.id);
            unlockBtn.setAttribute('aria-label', 'Unlock user ' + u.email);
            td.appendChild(unlockBtn);
            tr.appendChild(td);
            tbody.appendChild(tr);
        });
    }

    function searchUser() {
        const q = document.getElementById('userSearch').value.trim();
        if (!q) return;

        api('GET', '/admin/users?q=' + encodeURIComponent(q)).then(function(d) {
            const users = (d && d.users) ? d.users : [];
            _tableData['usersBody'] = users;
            renderUsersRows(users);
            setResultCount('userResultCount', users.length);
        }).catch(function(){});
    }

    function initUsers() {
        const searchInput = document.getElementById('userSearch');
        if (searchInput) {
            searchInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') { e.preventDefault(); searchUser(); }
            });
        }
    }

    // ========== Page: User Detail ==========

    function initUserDetail() {
        const path = window.location.pathname;
        const match = path.match(/\/admin\/ui\/users\/([^/]+)/);
        if (!match) return;
        const userId = match[1];

        api('GET', '/admin/users/' + encodeURIComponent(userId)).then(function(d) {
            if (!d || d.error) {
                document.getElementById('userFields').textContent = d ? d.error : 'User not found';
                return;
            }
            const fields = document.getElementById('userFields');
            fields.innerHTML = '';
            const pairs = [
                ['ID', d.id],
                ['Email', d.email],
                ['Display Name', d.display_name || '\u2014'],
                ['Verified', d.email_verified ? 'Yes' : 'No'],
                ['MFA Required', d.mfa_required ? 'Yes' : 'No'],
                ['Locked Until', d.locked_until ? fmtTime(d.locked_until) : 'No'],
                ['Created', fmtTime(d.created_at)]
            ];
            pairs.forEach(function(p) {
                const label = document.createElement('div');
                label.className = 'detail-label';
                label.textContent = p[0];
                fields.appendChild(label);
                const value = document.createElement('div');
                value.className = 'detail-value';
                value.textContent = p[1];
                fields.appendChild(value);
            });

            const actions = document.getElementById('userActions');
            if (actions) {
                actions.style.display = 'flex';
                actions.querySelectorAll('[data-action="lock-user-detail"]').forEach(function(btn) {
                    btn.setAttribute('data-id', userId);
                });
                actions.querySelectorAll('[data-action="unlock-user-detail"]').forEach(function(btn) {
                    btn.setAttribute('data-id', userId);
                });
            }
        }).catch(function(){});
    }

    // ========== Page: Audit ==========

    function queryAudit() {
        const eventType = document.getElementById('auditEventType').value;
        const userId = document.getElementById('auditUserId').value.trim();
        let params = '?limit=100';
        if (eventType) params += '&event_type=' + encodeURIComponent(eventType);
        if (userId) params += '&user_id=' + encodeURIComponent(userId);
        api('GET', '/admin/audit' + params).then(function(d) {
            const entries = (d && d.entries) ? d.entries : [];
            renderAuditTable('auditBody', entries, false);
            setResultCount('auditResultCount', entries.length);
        }).catch(function(){});
    }

    function initAudit() {
        queryAudit();
        // Allow Enter key in user ID field
        const uid = document.getElementById('auditUserId');
        if (uid) {
            uid.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') { e.preventDefault(); queryAudit(); }
            });
        }
        // Auto-query on event type change
        const sel = document.getElementById('auditEventType');
        if (sel) {
            sel.addEventListener('change', function() { queryAudit(); });
        }
    }

    // ========== Page: Clients ==========

    function renderClientsRows(clients) {
        const tbody = document.getElementById('clientsBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (clients.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'empty-state';
            td.textContent = 'No service clients';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        clients.forEach(function(c) {
            const tr = document.createElement('tr');
            appendCell(tr, c.name);
            // ID with copy
            const idTd = document.createElement('td');
            const idCode = document.createElement('code');
            idCode.textContent = c.id.substring(0, 8);
            idCode.title = c.id;
            idTd.appendChild(idCode);
            tr.appendChild(idTd);
            appendCell(tr, c.role);
            // Status badge
            const statusTd = document.createElement('td');
            const span = document.createElement('span');
            span.className = c.active ? 'badge badge-active' : 'badge badge-revoked';
            span.textContent = c.active ? 'Active' : 'Revoked';
            statusTd.appendChild(span);
            tr.appendChild(statusTd);
            appendCell(tr, timeAgo(c.created_at));
            // Action buttons
            const td = document.createElement('td');
            if (c.active) {
                const rotateBtn = document.createElement('button');
                rotateBtn.className = 'btn btn-sm';
                rotateBtn.textContent = 'Rotate';
                rotateBtn.setAttribute('data-action', 'rotate-client');
                rotateBtn.setAttribute('data-id', c.id);
                rotateBtn.setAttribute('aria-label', 'Rotate secret for ' + c.name);
                td.appendChild(rotateBtn);
                td.appendChild(document.createTextNode(' '));
                const revokeBtn = document.createElement('button');
                revokeBtn.className = 'btn btn-sm btn-danger';
                revokeBtn.textContent = 'Revoke';
                revokeBtn.setAttribute('data-action', 'revoke-client');
                revokeBtn.setAttribute('data-id', c.id);
                revokeBtn.setAttribute('aria-label', 'Revoke client ' + c.name);
                td.appendChild(revokeBtn);
            }
            tr.appendChild(td);
            tbody.appendChild(tr);
        });
    }

    function refreshClients() {
        api('GET', '/admin/clients').then(function(d) {
            if (!d || !d.clients) return;
            _tableData['clientsBody'] = d.clients;
            renderClientsRows(d.clients);
        }).catch(function(){});
    }

    function initClients() {
        refreshClients();
        setInterval(function() {
            if (!document.hidden) refreshClients();
        }, 60000);
    }

    // ========== Page: Admins ==========

    function renderAdminsRows(admins) {
        const tbody = document.getElementById('adminsBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        if (admins.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'empty-state';
            td.textContent = 'No admin accounts';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        admins.forEach(function(a) {
            const tr = document.createElement('tr');
            appendCell(tr, a.username);
            // Role badge
            const roleTd = document.createElement('td');
            const badge = document.createElement('span');
            badge.className = 'role-badge';
            badge.textContent = a.role;
            roleTd.appendChild(badge);
            tr.appendChild(roleTd);
            // TOTP status
            const totpTd = document.createElement('td');
            const totpSpan = document.createElement('span');
            totpSpan.className = a.totp_configured ? 'badge badge-active' : 'badge badge-revoked';
            totpSpan.textContent = a.totp_configured ? 'Yes' : 'No';
            totpTd.appendChild(totpSpan);
            tr.appendChild(totpTd);
            // Locked
            const lockedTd = document.createElement('td');
            if (a.locked_until) {
                const lockedSpan = document.createElement('span');
                lockedSpan.className = 'badge badge-locked';
                lockedSpan.textContent = 'Locked';
                lockedTd.appendChild(lockedSpan);
            } else {
                lockedTd.textContent = 'No';
            }
            tr.appendChild(lockedTd);
            appendCell(tr, timeAgo(a.last_login_at || ''));
            // Action buttons
            const td = document.createElement('td');
            const revokeBtn = document.createElement('button');
            revokeBtn.className = 'btn btn-sm btn-danger';
            revokeBtn.textContent = 'Revoke';
            revokeBtn.setAttribute('data-action', 'revoke-admin');
            revokeBtn.setAttribute('data-id', a.id);
            revokeBtn.setAttribute('aria-label', 'Revoke admin ' + a.username);
            td.appendChild(revokeBtn);
            tr.appendChild(td);
            tbody.appendChild(tr);
        });
    }

    function refreshAdmins() {
        api('GET', '/admin/admins').then(function(d) {
            if (!d || !d.admins) return;
            _tableData['adminsBody'] = d.admins;
            renderAdminsRows(d.admins);
        }).catch(function(){});
    }

    function initAdmins() {
        refreshAdmins();
    }

    // ========== Page: Config ==========

    function renderConfigRows(entries) {
        const tbody = document.getElementById('configBody');
        if (!tbody) return;
        tbody.innerHTML = '';
        // entries can be an array of {key, value} or an object.
        let keys;
        const isObj = !Array.isArray(entries);
        if (isObj) {
            keys = Object.keys(entries);
        } else {
            keys = entries.map(function(e) { return e.key; });
        }
        if (keys.length === 0) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 3;
            td.className = 'empty-state';
            td.textContent = 'No configuration entries';
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        keys.sort().forEach(function(k) {
            const val = isObj ? entries[k] : entries.find(function(e) { return e.key === k; }).value;
            const tr = document.createElement('tr');
            const keyTd = document.createElement('td');
            const keyCode = document.createElement('code');
            keyCode.textContent = k;
            keyTd.appendChild(keyCode);
            tr.appendChild(keyTd);
            appendCell(tr, val);
            // Actions
            const td = document.createElement('td');
            const editBtn = document.createElement('button');
            editBtn.className = 'btn btn-sm';
            editBtn.textContent = 'Edit';
            editBtn.setAttribute('data-action', 'edit-config');
            editBtn.setAttribute('data-key', k);
            editBtn.setAttribute('data-value', val);
            editBtn.setAttribute('aria-label', 'Edit config ' + k);
            td.appendChild(editBtn);
            td.appendChild(document.createTextNode(' '));
            const delBtn = document.createElement('button');
            delBtn.className = 'btn btn-sm btn-danger';
            delBtn.textContent = 'Delete';
            delBtn.setAttribute('data-action', 'delete-config');
            delBtn.setAttribute('data-key', k);
            delBtn.setAttribute('aria-label', 'Delete config ' + k);
            td.appendChild(delBtn);
            tr.appendChild(td);
            tbody.appendChild(tr);
        });
    }

    function refreshConfig() {
        api('GET', '/admin/config').then(function(d) {
            if (!d) return;
            const entries = d.entries || {};
            _tableData['configBody'] = entries;
            renderConfigRows(entries);
        }).catch(function(){});
    }

    function initConfig() {
        refreshConfig();
    }

    // ========== Page: TOTP Setup ==========

    function initTOTPSetup() {
        // Handled entirely via data-action delegation
    }

    // ========== Sidebar Toggle ==========

    function initSidebar() {
        const toggle = document.getElementById('sidebarToggle');
        const sidebar = document.getElementById('sidebar');
        if (toggle && sidebar) {
            toggle.addEventListener('click', function() {
                sidebar.classList.toggle('sidebar-collapsed');
            });
        }
    }

    // ========== Inline Form Helpers ==========

    function showForm(formId) {
        const form = document.getElementById(formId);
        if (!form) return;
        form.style.display = 'flex';
        // Auto-focus first input.
        const firstInput = form.querySelector('input');
        if (firstInput) firstInput.focus();
    }

    function hideForm(formId) {
        const form = document.getElementById(formId);
        if (!form) return;
        form.style.display = 'none';
    }

    // ========== Keyboard Shortcuts ==========

    function initKeyboardShortcuts() {
        document.addEventListener('keydown', function(e) {
            if (e.key !== 'Escape') return;
            // Modal is handled in confirmModal's own keydown listener.
            // Close inline forms.
            const forms = ['createClientForm', 'createAdminForm', 'addConfigForm'];
            for (let i = 0; i < forms.length; i++) {
                const form = document.getElementById(forms[i]);
                if (form && form.style.display !== 'none') {
                    form.style.display = 'none';
                    return;
                }
            }
        });
    }

    // ========== Event Delegation ==========

    document.addEventListener('click', function(e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.getAttribute('data-action');
        const id = btn.getAttribute('data-id');

        switch (action) {
            // ---- Layout ----
            case 'logout':
                api('POST', '/admin/auth/logout').then(function() {
                    sessionStorage.removeItem('admin_token');
                    window.location.href = '/admin/login';
                }).catch(function() {
                    sessionStorage.removeItem('admin_token');
                    window.location.href = '/admin/login';
                });
                break;

            // ---- Keys ----
            case 'rotate-key':
                confirmModal('Generate a new signing key?').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/keys/rotate').then(function(d) {
                        setLoading(btn, false);
                        if (d && d.kid) showToast('Key rotated: ' + d.kid, 'success');
                        refreshKeys();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;
            case 'refresh-keys':
                refreshKeys();
                break;
            case 'revoke-key':
                confirmModal('Revoke key ' + id + '?').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('DELETE', '/admin/keys/' + encodeURIComponent(id)).then(function() {
                        setLoading(btn, false);
                        showToast('Key revoked', 'success');
                        refreshKeys();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;

            // ---- Sessions ----
            case 'revoke-all-sessions':
                confirmModal('Revoke ALL admin sessions? You will be logged out.').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/sessions/revoke-all').then(function() {
                        sessionStorage.removeItem('admin_token');
                        window.location.href = '/admin/login';
                    }).catch(function() { setLoading(btn, false); });
                });
                break;
            case 'refresh-sessions':
                refreshSessions();
                break;

            // ---- Users ----
            case 'search-user':
                searchUser();
                break;
            case 'lock-user':
            case 'lock-user-detail':
                confirmModal('Lock user ' + (id ? id.substring(0, 8) : '') + '?').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/users/' + encodeURIComponent(id) + '/lock', { duration: '24h' }).then(function() {
                        setLoading(btn, false);
                        showToast('User locked for 24h', 'success');
                        if (action === 'lock-user') searchUser();
                        else initUserDetail();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;
            case 'unlock-user':
            case 'unlock-user-detail':
                confirmModal('Unlock user?').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/users/' + encodeURIComponent(id) + '/unlock').then(function() {
                        setLoading(btn, false);
                        showToast('User unlocked', 'success');
                        if (action === 'unlock-user') searchUser();
                        else initUserDetail();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;

            // ---- Audit ----
            case 'query-audit':
                queryAudit();
                break;

            // ---- Clients ----
            case 'show-create-client':
                showForm('createClientForm');
                break;
            case 'hide-create-client':
                hideForm('createClientForm');
                break;
            case 'create-client': {
                const cname = document.getElementById('clientName').value.trim();
                const crole = document.getElementById('clientRole').value.trim();
                if (!cname) { showToast('Client name is required', 'error'); break; }
                setLoading(btn, true);
                api('POST', '/admin/clients', { name: cname, role: crole || 'service', scopes: [], redirect_uris: [] }).then(function(d) {
                    setLoading(btn, false);
                    if (d && d.error) { showToast('Error: ' + d.error, 'error'); return; }
                    if (d && d.secret) {
                        showToast('Client created! Secret copied to clipboard.', 'success');
                        copyToClipboard(d.secret);
                    }
                    hideForm('createClientForm');
                    document.getElementById('clientName').value = '';
                    document.getElementById('clientRole').value = '';
                    refreshClients();
                }).catch(function() { setLoading(btn, false); });
                break;
            }
            case 'refresh-clients':
                refreshClients();
                break;
            case 'rotate-client':
                confirmModal('Rotate client secret? The old secret will stop working.').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/clients/' + encodeURIComponent(id) + '/rotate').then(function(d) {
                        setLoading(btn, false);
                        if (d && d.secret) {
                            showToast('Secret rotated! Copied to clipboard.', 'success');
                            copyToClipboard(d.secret);
                        }
                        refreshClients();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;
            case 'revoke-client':
                confirmModal('Revoke client? This cannot be undone.').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/clients/' + encodeURIComponent(id) + '/revoke').then(function() {
                        setLoading(btn, false);
                        showToast('Client revoked', 'success');
                        refreshClients();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;

            // ---- Admins ----
            case 'show-create-admin':
                showForm('createAdminForm');
                break;
            case 'hide-create-admin':
                hideForm('createAdminForm');
                break;
            case 'create-admin': {
                const auser = document.getElementById('adminUsername').value.trim();
                const apass = document.getElementById('adminPassword').value;
                const arole = document.getElementById('adminRole').value;
                if (!auser || !apass) { showToast('Username and password required', 'error'); break; }
                if (apass.length < 20) { showToast('Password must be at least 20 characters', 'error'); break; }
                setLoading(btn, true);
                api('POST', '/admin/admins', { username: auser, password: apass, role: arole }).then(function(d) {
                    setLoading(btn, false);
                    if (d && d.error) { showToast('Error: ' + d.error, 'error'); return; }
                    showToast('Admin ' + auser + ' created', 'success');
                    hideForm('createAdminForm');
                    document.getElementById('adminUsername').value = '';
                    document.getElementById('adminPassword').value = '';
                    refreshAdmins();
                }).catch(function() { setLoading(btn, false); });
                break;
            }
            case 'refresh-admins':
                refreshAdmins();
                break;
            case 'revoke-admin':
                confirmModal('Revoke admin account? This is irreversible.').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('POST', '/admin/admins/' + encodeURIComponent(id) + '/revoke').then(function(d) {
                        setLoading(btn, false);
                        if (d && d.error) { showToast('Error: ' + d.error, 'error'); return; }
                        showToast('Admin revoked', 'success');
                        refreshAdmins();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;

            // ---- Config ----
            case 'show-add-config':
                showForm('addConfigForm');
                break;
            case 'hide-add-config':
                hideForm('addConfigForm');
                break;
            case 'add-config': {
                const ck = document.getElementById('configKey').value.trim();
                const cv = document.getElementById('configValue').value.trim();
                if (!ck) { showToast('Key is required', 'error'); break; }
                setLoading(btn, true);
                api('PUT', '/admin/config/' + encodeURIComponent(ck), { value: cv }).then(function(d) {
                    setLoading(btn, false);
                    if (d && d.error) { showToast('Error: ' + d.error, 'error'); return; }
                    showToast('Config saved', 'success');
                    hideForm('addConfigForm');
                    document.getElementById('configKey').value = '';
                    document.getElementById('configValue').value = '';
                    refreshConfig();
                }).catch(function() { setLoading(btn, false); });
                break;
            }
            case 'edit-config': {
                const eKey = btn.getAttribute('data-key');
                const eVal = btn.getAttribute('data-value');
                document.getElementById('configKey').value = eKey;
                document.getElementById('configValue').value = eVal;
                showForm('addConfigForm');
                break;
            }
            case 'delete-config': {
                const dKey = btn.getAttribute('data-key');
                confirmModal('Delete config key "' + dKey + '"?').then(function(yes) {
                    if (!yes) return;
                    setLoading(btn, true);
                    api('DELETE', '/admin/config/' + encodeURIComponent(dKey)).then(function(d) {
                        setLoading(btn, false);
                        if (d && d.error) { showToast('Error: ' + d.error, 'error'); return; }
                        showToast('Config deleted', 'success');
                        refreshConfig();
                    }).catch(function() { setLoading(btn, false); });
                });
                break;
            }
            case 'refresh-config':
                refreshConfig();
                break;

            // ---- TOTP Setup ----
            case 'generate-totp':
                setLoading(btn, true);
                api('POST', '/admin/admins/me/totp/setup').then(function(d) {
                    setLoading(btn, false);
                    if (d && d.error) {
                        showToast('Error: ' + d.error, 'error');
                        return;
                    }
                    if (d && d.secret) {
                        document.getElementById('totpSecret').textContent = d.secret;
                        document.getElementById('totpUri').textContent = d.otpauth_uri || '';
                        document.getElementById('totpStep1').style.display = 'none';
                        document.getElementById('totpStep2').style.display = 'block';
                    }
                }).catch(function() { setLoading(btn, false); });
                break;
            case 'verify-totp': {
                const code = document.getElementById('totpVerifyCode').value.trim();
                if (!code || code.length !== 6) { showToast('Enter a 6-digit code', 'error'); break; }
                setLoading(btn, true);
                api('POST', '/admin/admins/me/totp/verify', { code: code }).then(function(d) {
                    setLoading(btn, false);
                    if (d && d.error) {
                        showToast('Invalid code. Try again.', 'error');
                        return;
                    }
                    if (d && d.status === 'totp_verified') {
                        document.getElementById('totpStep2').style.display = 'none';
                        document.getElementById('totpStep3').style.display = 'block';
                        showToast('TOTP configured successfully!', 'success');
                    }
                }).catch(function() { setLoading(btn, false); });
                break;
            }

            // ---- Copy ----
            case 'copy': {
                const targetId = btn.getAttribute('data-copy-target');
                const target = document.getElementById(targetId);
                if (target) copyToClipboard(target.textContent, btn);
                break;
            }
        }
    });

    // ========== Page Router ==========

    document.addEventListener('DOMContentLoaded', function() {
        const page = document.body.dataset.page;

        // Client-side auth guard: redirect to login if no token (except on login page)
        if (page !== 'login' && !token) {
            window.location.href = '/admin/login';
            return;
        }

        initSidebar();
        initKeyboardShortcuts();
        initSortableHeaders();

        switch (page) {
            case 'login':       initLogin(); break;
            case 'dashboard':   initDashboard(); break;
            case 'keys':        initKeys(); break;
            case 'sessions':    initSessions(); break;
            case 'users':       initUsers(); break;
            case 'user_detail': initUserDetail(); break;
            case 'audit':       initAudit(); break;
            case 'clients':     initClients(); break;
            case 'admins':      initAdmins(); break;
            case 'config':      initConfig(); break;
            case 'totp_setup':  initTOTPSetup(); break;
        }

        // Stop auto-refresh timers when tab is hidden
        document.addEventListener('visibilitychange', function() {
            // Timers check document.hidden on each tick, no cleanup needed
        });
    });
})();
