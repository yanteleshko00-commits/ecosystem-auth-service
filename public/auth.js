const $ = selector => document.querySelector(selector);
const params = new URLSearchParams(location.search);
const nextPath = (() => {
  const value = params.get('next') || '/';
  return value.startsWith('/') && !value.startsWith('//') && !value.includes('\\') ? value : '/';
})();
let mode = 'login';
let verifyRequestBusy = false;

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
function setBusy(button, busy, busyText = 'Отправляем…') {
  if (!button) return;
  if (busy) {
    if (!button.dataset.idleText) button.dataset.idleText = button.textContent;
    button.disabled = true;
    button.textContent = busyText;
    button.setAttribute('aria-busy', 'true');
  } else {
    button.disabled = false;
    button.textContent = button.dataset.idleText || button.textContent;
    button.removeAttribute('aria-busy');
  }
}
async function requestJson(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    let data = {};
    try { data = await response.json(); } catch { /* empty or non-JSON response */ }
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
  closeVerifyModal();
  $('#heading').textContent = mode === 'login' ? 'Войти в аккаунт' : 'Создать аккаунт';
  $('#subheading').textContent = mode === 'login'
    ? 'Один аккаунт для самостоятельных сервисов экосистемы.'
    : 'Подтвердите email, чтобы пользоваться всеми сервисами.';
  $('#password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  $('#name-field').classList.toggle('hidden', mode !== 'register');
  $('#name').required = mode === 'register';
  $('#submit').textContent = mode === 'login' ? 'Войти' : 'Зарегистрироваться';
  document.querySelectorAll('.tab').forEach(button =>
    button.classList.toggle('active', button.dataset.mode === mode)
  );
  $('#auth-form').classList.remove('hidden');
  $('#forgot').classList.toggle('hidden', mode !== 'login');
  showMessage('');
}
document.querySelectorAll('.tab').forEach(button =>
  button.addEventListener('click', () => setMode(button.dataset.mode))
);

$('#auth-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('#submit');
  if (submit.disabled) return;
  const payload = { email: $('#email').value.trim(), password: $('#password').value };
  if (mode === 'register') payload.name = $('#name').value.trim();
  setBusy(submit, true, mode === 'login' ? 'Входим…' : 'Создаём аккаунт…');
  showMessage('');
  try {
    const endpoint = mode === 'login' ? '/v1/auth/login' : '/v1/auth/register';
    const data = await requestJson(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (mode === 'login') {
      location.assign(nextPath);
      return;
    }
    $('#forgot').classList.add('hidden');
    openVerifyModal(payload.email, data.message || 'Код отправлен. Проверьте почту.');
  } catch (error) {
    showMessage(error.message || 'Не удалось выполнить запрос.');
  } finally {
    setBusy(submit, false);
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
  setBusy(submit, true, 'Проверяем…');
  try {
    await requestJson('/v1/auth/verify-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    closeVerifyModal();
    setMode('login');
    $('#email').value = payload.email;
    showMessage('Email подтверждён. Теперь войдите.', true);
  } catch (error) {
    showVerifyMessage(error.message || 'Не удалось проверить код.');
  } finally {
    setBusy(submit, false);
  }
});

async function sendVerificationCode(email, button = null) {
  if (verifyRequestBusy) return;
  verifyRequestBusy = true;
  setBusy(button, true, 'Отправляем…');
  try {
    const data = await requestJson('/v1/auth/resend-verification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    showVerifyMessage(
      data.message || 'Если аккаунт требует подтверждения, код отправлен на почту.',
      'ok'
    );
  } catch (error) {
    showVerifyMessage(error.message || 'Не удалось отправить код.');
  } finally {
    verifyRequestBusy = false;
    setBusy(button, false);
  }
}

$('#verify-email-action').addEventListener('click', async () => {
  const emailInput = $('#email');
  const email = emailInput.value.trim();
  if (!email) {
    showMessage('Сначала укажите email.');
    emailInput.focus();
    return;
  }
  if (!emailInput.checkValidity()) {
    showMessage('Проверьте правильность email.');
    emailInput.focus();
    return;
  }
  if (verifyRequestBusy) return;
  openVerifyModal(email, 'Отправляем код на почту…');
  await sendVerificationCode(email, $('#verify-email-action'));
});

$('#resend').addEventListener('click', async () => {
  const email = $('#verify-email').value.trim();
  if (!email || verifyRequestBusy) return;
  await sendVerificationCode(email, $('#resend'));
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
    const newPassword = prompt('Введите новый пароль (не менее 10 символов):');
    if (!newPassword) return;
    await requestJson('/v1/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code: code.trim(), newPassword })
    });
    showMessage('Пароль изменён. Теперь войдите.', true);
  } catch (error) {
    showMessage(error.message || 'Не удалось восстановить пароль.');
  }
});

function mapError(code) {
  const messages = {
    invalid_credentials: 'Неверный email или пароль.',
    email_not_verified: 'Сначала подтвердите email.',
    invalid_or_expired_code: 'Код неверный или срок его действия истёк.',
    invalid_verification_data: 'Введите корректный шестизначный код.',
    email_delivery_unavailable: 'Письмо не отправлено. Проверьте настройки Brevo SMTP и подтверждённый адрес отправителя.',
    account_already_exists: 'Аккаунт уже существует. Войдите или восстановите пароль.',
    invalid_registration_data: 'Проверьте имя, email и пароль. Имя обязательно, пароль должен содержать минимум 10 символов.',
    invalid_email: 'Проверьте правильность email.',
    origin_not_allowed: 'Запрос с этого адреса не разрешён.'
  };
  return messages[code] || 'Не удалось выполнить запрос. Проверьте данные и попробуйте ещё раз.';
}
