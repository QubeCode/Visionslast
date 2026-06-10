/**
 * CTRL+ — Couche sécurité client (formulaires, cookies, validation).
 * Les en-têtes HTTP (_headers / .htaccess) complètent cette protection côté serveur.
 */
(function (global) {
  'use strict';

  var FORM_EMAIL = 'Quincy.bordey@gmail.com';
  var FORM_URL = 'https://formsubmit.co/ajax/' + encodeURIComponent(FORM_EMAIL);
  var LIMITS = { name: 100, email: 254, message: 5000, subject: 120, profile: 80, type: 80, amount: 12 };
  var RATE_MAX = 3;
  var RATE_WINDOW_MS = 600000;

  function sanitize(str, max) {
    if (typeof str !== 'string') return '';
    return str.trim().slice(0, max).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F<>]/g, '');
  }

  function isValidEmail(email) {
    if (!email || email.length > LIMITS.email) return false;
    return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(email);
  }

  function isBot(form) {
    var honey = form.querySelector('[name="website"], [name="_honey"]');
    return honey && honey.value.trim().length > 0;
  }

  function checkRateLimit(key) {
    var storageKey = 'ctrl_rl_' + key.replace(/[^a-z0-9_-]/gi, '');
    var now = Date.now();
    var times = [];
    try {
      times = JSON.parse(localStorage.getItem(storageKey) || '[]');
    } catch (e) {
      times = [];
    }
    times = times.filter(function (t) { return now - t < RATE_WINDOW_MS; });
    if (times.length >= RATE_MAX) return false;
    times.push(now);
    try {
      localStorage.setItem(storageKey, JSON.stringify(times));
    } catch (e) { /* quota privée */ }
    return true;
  }

  function showRateLimitError(errorEl) {
    if (!errorEl) return;
    var msg = 'Trop de tentatives. Réessaie dans 10 minutes.';
    if (errorEl.dataset.defaultMsg) {
      errorEl.textContent = msg;
    } else {
      errorEl.dataset.defaultMsg = errorEl.textContent;
      errorEl.textContent = msg;
    }
    errorEl.classList.add('show');
  }

  function resetErrorMsg(errorEl) {
    if (errorEl && errorEl.dataset.defaultMsg) {
      errorEl.textContent = errorEl.dataset.defaultMsg;
    }
  }

  /**
   * @param {object} opts
   * @param {HTMLFormElement} opts.form
   * @param {string} opts.rateKey
   * @param {string} opts.subjectPrefix
   * @param {HTMLElement} opts.successEl
   * @param {HTMLElement} opts.errorEl
   * @param {HTMLButtonElement} opts.btn
   * @param {string} opts.btnLabel
   * @param {function} opts.buildFields — retourne les champs métier (sanitisés côté appelant)
   */
  async function secureSubmit(opts) {
    var form = opts.form;
    var successEl = opts.successEl;
    var errorEl = opts.errorEl;
    var btn = opts.btn;
    var btnLabel = opts.btnLabel || 'Envoyer';

    successEl.classList.remove('show');
    errorEl.classList.remove('show');
    resetErrorMsg(errorEl);

    if (isBot(form)) {
      successEl.classList.add('show');
      form.reset();
      return { ok: true, silent: true };
    }

    if (!form.checkValidity()) {
      form.reportValidity();
      return { ok: false };
    }

    var nameEl = form.querySelector('[name="name"]');
    var emailEl = form.querySelector('[name="email"]');
    var name = nameEl ? sanitize(nameEl.value, LIMITS.name) : '';
    var email = emailEl ? sanitize(emailEl.value, LIMITS.email) : '';

    if (!name || name.length < 2) {
      if (nameEl) nameEl.setCustomValidity('Nom trop court (2 caractères minimum).');
      nameEl && nameEl.reportValidity();
      nameEl && nameEl.setCustomValidity('');
      return { ok: false };
    }
    if (!isValidEmail(email)) {
      if (emailEl) emailEl.setCustomValidity('Adresse email invalide.');
      emailEl && emailEl.reportValidity();
      emailEl && emailEl.setCustomValidity('');
      return { ok: false };
    }

    if (!checkRateLimit(opts.rateKey || opts.subjectPrefix)) {
      showRateLimitError(errorEl);
      return { ok: false };
    }

    btn.disabled = true;
    btn.textContent = 'Envoi en cours…';

    var fields = typeof opts.buildFields === 'function' ? opts.buildFields(form, sanitize) : {};
    var payload = Object.assign({
      name: name,
      email: email,
      _subject: opts.subjectPrefix,
      _template: 'table',
      _captcha: 'false',
      _honey: ''
    }, fields);

    try {
      var res = await fetch(FORM_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload),
        credentials: 'omit',
        referrerPolicy: 'strict-origin-when-cross-origin',
        mode: 'cors'
      });

      if (!res.ok) throw new Error('HTTP ' + res.status);

      successEl.classList.add('show');
      form.reset();
      successEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return { ok: true };
    } catch (err) {
      errorEl.classList.add('show');
      return { ok: false };
    } finally {
      btn.disabled = false;
      btn.textContent = btnLabel;
    }
  }

  function initCookieBanner() {
    var banner = document.getElementById('cookieBanner');
    var accept = document.getElementById('cookieAccept');
    if (!banner || !accept) return;
    try {
      if (!localStorage.getItem('ctrl_cookies')) banner.classList.add('show');
    } catch (e) {
      banner.classList.add('show');
    }
    accept.addEventListener('click', function () {
      try { localStorage.setItem('ctrl_cookies', '1'); } catch (e) { /* ignore */ }
      banner.classList.remove('show');
    });
  }

  function bindForm(form, config) {
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      secureSubmit(Object.assign({ form: form }, config));
    });
  }

  global.CTRLSecurity = {
    sanitize: sanitize,
    isValidEmail: isValidEmail,
    secureSubmit: secureSubmit,
    bindForm: bindForm,
    initCookieBanner: initCookieBanner,
    LIMITS: LIMITS
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCookieBanner);
  } else {
    initCookieBanner();
  }
})(typeof window !== 'undefined' ? window : this);
