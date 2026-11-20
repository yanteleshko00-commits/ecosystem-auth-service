const $ = selector => document.querySelector(selector);
const params = new URLSearchParams(location.search);
const nextPath = (() => {
  const value = params.get('next') || '/';
  return value.startsWith('/') && !value.startsWith('//') && !value.includes('\\') ? value : '/';
})();
let mode = 'login';
let loginCodeRequested = false;
let passwordLoginMode = false;
let verifyRequestBusy = false;
let loginResendTimer = null;

function showMessage(text, ok = false) {
  const node = $('#message');
  node.textContent = text || '';
  node.classList.toggle('ok', ok);
}
function showVerifyMessage(text, kind = 'error') {
  const node = $('#verify-message');
  node.textContent = text || '';
  node.classList.toggle('ok', kind === 'ok');
  node.classList.toggle('loading', kind === 'loading');
}
async function requestJson(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal, credentials: 'same-origin' });
    let data = {};
    try { data = await response.json(); } catch {}
    if (!response.ok) throw new Error(data.message || mapError(data.error));
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Сервер долго не отвечает. Проверьте соединение и попробуйте ещё раз.');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
function openVerifyModal(email, message = '') {
  $('#verify-email').value = email;
  $('#code').value = '';
  $('#verify-modal').classList.remove('hidden');
  document.body.classList.add('modal-open');
  showVerifyMessage(message, message ? 'loading' : 'error');
  requestAnimationFrame(() => $('#code').focus());
}
function closeVerifyModal() {
  $('#verify-modal').classList.add('hidden');
  document.body.classList.remove('modal-open');
}
$('#close-verify').addEventListener('click', closeVerifyModal);
$('#verify-modal').addEventListener('click', event => {
  if (event.target === $('#verify-modal')) closeVerifyModal();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && !$('#verify-modal').classList.contains('hidden')) closeVerifyModal();
});

function setMode(nextMode) {
  mode = nextMode;
  loginCodeRequested = false;
  passwordLoginMode = false;
  closeVerifyModal();
  if (loginResendTimer) clearInterval(loginResendTimer);
  $('#heading').textContent = mode === 'login' ? 'Войти в NEXORA ID' : 'Создать NEXORA ID';
  $('#subheading').textContent = mode === 'login'
    ? 'Один аккаунт для всех сервисов. Войдите по коду из письма.'
    : 'Создайте один аккаунт и используйте его во всей экосистеме.';
  $('#name-field').classList.toggle('hidden', mode !== 'register');
  $('#name').required = mode === 'register';
  $('#password-field').classList.toggle('hidden', mode === 'login');
  $('#password').required = mode === 'register';
  $('#login-code-field').classList.add('hidden');
  $('#login-code-resend').classList.add('hidden');
  $('#verify-email-action').classList.remove('hidden');
  $('#verify-email-action').textContent = mode === 'register' ? 'Подтвердить email' : 'Не пришло письмо?';
  $('#submit').textContent = mode === 'login' ? 'Получить код' : 'Создать аккаунт';
  $('#password-login-toggle').classList.toggle('hidden', mode !== 'login');
  $('#password-login-toggle').textContent = 'Войти по паролю';
  $('#forgot').classList.add('hidden');
  document.querySelectorAll('.tab').forEach(button =>
    button.classList.toggle('active', button.dataset.mode === mode)
  );
  showMessage('');
}
document.querySelectorAll('.tab').forEach(button =>
  button.addEventListener('click', () => setMode(button.dataset.mode))
);

$('#password-login-toggle').addEventListener('click', () => {
  passwordLoginMode = !passwordLoginMode;
  loginCodeRequested = false;
  $('#password').required = passwordLoginMode;
  $('#password-field').classList.toggle('hidden', !passwordLoginMode);
  $('#login-code-field').classList.add('hidden');
  $('#submit').textContent = passwordLoginMode ? 'Войти по паролю' : 'Получить код';
  $('#password-login-toggle').textContent = passwordLoginMode ? 'Войти по коду из письма' : 'Войти по паролю';
  $('#forgot').classList.toggle('hidden', !passwordLoginMode);
  showMessage('');
});

function beginLoginResendCooldown() {
  const button = $('#login-code-resend');
  button.disabled = true;
  let seconds = 30;
  button.textContent = 'Повторить через ' + seconds + ' сек.';
  if (loginResendTimer) clearInterval(loginResendTimer);
  loginResendTimer = setInterval(() => {
    seconds -= 1;
    if (seconds <= 0) {
      clearInterval(loginResendTimer);
      button.disabled = false;
      button.textContent = 'Отправить код повторно';
    } else {
      button.textContent = 'Повторить через ' + seconds + ' сек.';
    }
  }, 1000);
}

async function sendLoginCode(email) {
  if (verifyRequestBusy) return;
  verifyRequestBusy = true;
  try {
    const data = await requestJson('/v1/auth/send-login-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    loginCodeRequested = true;
    $('#login-code-field').classList.remove('hidden');
    $('#login-code-resend').classList.remove('hidden');
    $('#submit').textContent = 'Подтвердить и войти';
    showMessage(data.message || 'Проверьте почту и введите шестизначный код.', true);
    beginLoginResendCooldown();
    $('#login-code').focus();
  } catch (error) {
    showMessage(error.message || 'Не удалось отправить код.');
  } finally {
    verifyRequestBusy = false;
  }
}
$('#login-code-resend').addEventListener('click', async () => {
  const email = $('#email').value.trim();
  if (!email || verifyRequestBusy) return;
  await sendLoginCode(email);
});

$('#auth-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('#submit');
  if (submit.disabled) return;
  const email = $('#email').value.trim();
  if (!email || !$('#email').checkValidity()) {
    showMessage('Введите корректный адрес электронной почты.');
    $('#email').focus();
    return;
  }

  if (mode === 'login' && !passwordLoginMode && !loginCodeRequested) {
    await sendLoginCode(email);
    return;
  }

  const originalText = submit.textContent;
  submit.disabled = true;
  submit.textContent = mode === 'login' ? 'Проверяем…' : 'Создаём аккаунт…';
  showMessage('');
  try {
    if (mode === 'login') {
      if (passwordLoginMode) {
        await requestJson('/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password: $('#password').value })
        });
      } else {
        const code = $('#login-code').value.trim();
        if (!/^\d{6}$/.test(code)) throw new Error('Введите шестизначный код из письма.');
        await requestJson('/v1/auth/verify-login-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, code })
        });
      }
      location.assign(nextPath);
      return;
    }

    const payload = {
      name: $('#name').value.trim(),
      email,
      password: $('#password').value
    };
    await requestJson('/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    openVerifyModal(email, 'Код подтверждения отправлен. Проверьте Входящие и Спам.');
  } catch (error) {
    showMessage(error.message || 'Не удалось выполнить запрос.');
  } finally {
    submit.disabled = false;
    submit.textContent = originalText;
  }
});

$('#verify-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('#verify-submit');
  if (submit.disabled) return;
  const payload = { email: $('#verify-email').value.trim(), code: $('#code').value.trim() };
  if (!/^\d{6}$/.test(payload.code)) {
    showVerifyMessage('Введите ровно 6 цифр.');
    return;
  }
  const originalText = submit.textContent;
  submit.disabled = true;
  submit.textContent = 'Проверяем…';
  try {
    await requestJson('/v1/auth/verify-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    showVerifyMessage('Email подтверждён. Выполняем вход…', 'ok');
    location.assign(nextPath);
  } catch (error) {
    showVerifyMessage(error.message || 'Не удалось проверить код.');
  } finally {
    submit.disabled = false;
    submit.textContent = originalText;
  }
});

async function sendVerificationCode(email, button) {
  if (verifyRequestBusy) return;
  verifyRequestBusy = true;
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = 'Отправляем…';
  try {
    const data = await requestJson('/v1/auth/resend-verification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    showVerifyMessage(data.message || 'Если аккаунт требует подтверждения, код отправлен.', 'ok');
  } catch (error) {
    showVerifyMessage(error.message || 'Не удалось отправить код.');
  } finally {
    verifyRequestBusy = false;
    button.disabled = false;
    button.textContent = originalText;
  }
}
$('#verify-email-action').addEventListener('click', async () => {
  const emailInput = $('#email');
  const email = emailInput.value.trim();
  if (!email || !emailInput.checkValidity()) {
    showMessage('Введите корректный адрес электронной почты.');
    emailInput.focus();
    return;
  }
  openVerifyModal(email, 'Отправляем код подтверждения…');
  await sendVerificationCode(email, $('#verify-email-action'));
});
$('#resend').addEventListener('click', async () => {
  const email = $('#verify-email').value.trim();
  if (email) await sendVerificationCode(email, $('#resend'));
});

$('#forgot').addEventListener('click', async () => {
  const email = $('#email').value.trim();
  if (!email) return showMessage('Сначала укажите email в поле выше.');
  try {
    const data = await requestJson('/v1/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    showMessage(data.message || 'Если аккаунт существует, на него отправлен код восстановления.');
    const code = prompt('Введите шестизначный код из письма:');
    if (!code) return;
    const newPassword = prompt('Введите новый пароль (не менее 6 символов):');
    if (!newPassword) return;
    await requestJson('/v1/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code: code.trim(), newPassword })
    });
    showMessage('Пароль изменён. Теперь можно войти по email-коду.', true);
    setMode('login');
  } catch (error) {
    showMessage(error.message || 'Не удалось восстановить пароль.');
  }
});

function mapError(code) {
  const messages = {
    invalid_credentials: 'Неверная почта или пароль.',
    invalid_login_data: 'Проверьте адрес почты и пароль.',
    email_not_verified: 'Сначала подтвердите электронную почту.',
    invalid_or_expired_code: 'Код неверный или срок его действия истёк.',
    invalid_verification_data: 'Введите корректный шестизначный код.',
    email_delivery_unavailable: 'Письмо не отправлено. Проверьте почтовые настройки и адрес отправителя.',
    account_already_exists: 'Аккаунт уже существует. Войдите или подтвердите email.',
    invalid_registration_data: 'Проверьте имя и email. Пароль должен содержать минимум 6 символов.',
    invalid_email: 'Проверьте правильность email.',
    origin_not_allowed: 'Запрос с этого адреса не разрешён.'
  };
  return messages[code] || 'Не удалось выполнить запрос. Проверьте данные и попробуйте ещё раз.';
}

setMode(params.get('mode') === 'register' ? 'register' : 'login');
