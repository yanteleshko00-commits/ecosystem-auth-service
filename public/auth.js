const $ = selector => document.querySelector(selector);
const params = new URLSearchParams(location.search);
const nextPath = (() => {
  const value = params.get('next') || '/';
  return value.startsWith('/') && !value.startsWith('//') && !value.includes('\\') ? value : '/';
})();
let mode = 'login';

function showVerifyMessage(text, ok = false) {
  const node = $('#verify-message');
  node.textContent = text;
  node.classList.toggle('ok', ok);
}
function openVerifyModal(email) {
  $('#verify-email').value = email;
  $('#code').value = '';
  $('#verify-modal').classList.remove('hidden');
  showVerifyMessage('');
  setTimeout(() => $('#code').focus(), 50);
}
function closeVerifyModal() { $('#verify-modal').classList.add('hidden'); }
$('#close-verify').addEventListener('click', closeVerifyModal);
$('#verify-modal').addEventListener('click', event => { if (event.target === $('#verify-modal')) closeVerifyModal(); });
function showMessage(text, ok = false) {
  const node = $('#message');
  node.textContent = text;
  node.classList.toggle('ok', ok);
}
function setMode(nextMode) {
  mode = nextMode;
  $('#heading').textContent = mode === 'login' ? 'Войти в аккаунт' : 'Создать аккаунт';
  $('#subheading').textContent = mode === 'login' ? 'Один аккаунт для самостоятельных сервисов экосистемы.' : 'Подтвердите email, чтобы пользоваться всеми сервисами.';
  $('#password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  $('#name-field').classList.toggle('hidden', mode !== 'register');
  $('#name').required = mode === 'register';
  $('#submit').textContent = mode === 'login' ? 'Войти' : 'Зарегистрироваться';
  document.querySelectorAll('.tab').forEach(button => button.classList.toggle('active', button.dataset.mode === mode));
  $('#verify-form').classList.add('hidden');
  $('#auth-form').classList.remove('hidden');
  $('#forgot').classList.toggle('hidden', mode !== 'login');
  showMessage('');
}

document.querySelectorAll('.tab').forEach(button => button.addEventListener('click', () => setMode(button.dataset.mode)));
$('#auth-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('#submit');
  submit.disabled = true;
  showMessage('');
  const payload = { email: $('#email').value.trim(), password: $('#password').value };
  if (mode === 'register') payload.name = $('#name').value.trim();
  try {
    const response = await fetch(`/v1/auth/${mode === 'login' ? 'login' : 'register'}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || mapError(data.error));
    if (mode === 'login') {
      location.assign(nextPath);
      return;
    }
    $('#verify-email').value = payload.email;
    $('#auth-form').classList.add('hidden');
    $('#verify-form').classList.remove('hidden');
    $('#forgot').classList.add('hidden');
    showMessage(data.message || 'Код отправлен на почту.', true);
  } catch (error) {
    showMessage(error.message || 'Не удалось выполнить запрос.');
  } finally {
    submit.disabled = false;
  }
});

$('#verify-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = $('#verify-submit');
  const payload = { email: $('#verify-email').value.trim(), code: $('#code').value.trim() };
  if (!/^\\d{6}$/.test(payload.code)) return showVerifyMessage('Введите ровно 6 цифр.');
  submit.disabled = true;
  try {
    const response = await fetch('/v1/auth/verify-email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await response.json();
    if (!response.ok) throw new Error(mapError(data.error));
    closeVerifyModal(); setMode('login'); $('#email').value = payload.email;
    showMessage('Email подтверждён. Теперь войдите.', true);
  } catch (error) { showVerifyMessage(error.message); }
  finally { submit.disabled = false; }
});

$('#resend').addEventListener('click', async () => {
  try {
    const response = await fetch('/v1/auth/resend-verification', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: $('#verify-email').value.trim() }) });
    const data = await response.json();
    if (!response.ok) throw new Error(mapError(data.error));
    showVerifyMessage(data.message || 'Новый код отправлен.', true);
  } catch (error) { showVerifyMessage(error.message); }
});

$('#verify-email-action').addEventListener('click', async () => {
  const email = $('#email').value.trim();
  if (!email) return showMessage('Сначала укажите email.');
  const button = $('#verify-email-action');
  button.disabled = true;
  try {
    const response = await fetch('/v1/auth/resend-verification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(mapError(data.error));
    openVerifyModal(email);
    showMessage(data.message || 'Если аккаунт не подтверждён, код отправлен на почту.', true);
  } catch (error) {
    showMessage(error.message || 'Не удалось отправить код.');
  } finally {
    button.disabled = false;
  }
});

$('#forgot').addEventListener('click', async () => {
  const email = $('#email').value.trim();
  if (!email) return showMessage('Сначала укажите email в поле выше.');
  try {
    const response = await fetch('/v1/auth/forgot-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
    const data = await response.json();
    if (!response.ok) throw new Error(mapError(data.error));
    const code = prompt('Введите шестизначный код из письма:');
    if (!code) return;
    const newPassword = prompt('Введите новый пароль (не менее 10 символов):');
    if (!newPassword) return;
    const reset = await fetch('/v1/auth/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, code, newPassword }) });
    const result = await reset.json();
    if (!reset.ok) throw new Error(mapError(result.error));
    showMessage('Пароль изменён. Теперь войдите.', true);
  } catch (error) { showMessage(error.message); }
});

function mapError(code) {
  const messages = {
    invalid_credentials: 'Неверный email или пароль.',
    email_not_verified: 'Сначала подтвердите email.',
    invalid_or_expired_code: 'Код неверный или срок его действия истёк.',
    email_delivery_unavailable: 'Не настроена отправка писем. Обратитесь к администратору.',
    account_already_exists: 'Аккаунт уже существует. Войдите или восстановите пароль.',
    invalid_registration_data: 'Проверьте имя, email и пароль. Имя обязательно, пароль должен содержать минимум 10 символов.'
  };
  return messages[code] || 'Не удалось выполнить запрос. Проверьте данные и попробуйте ещё раз.';
}
