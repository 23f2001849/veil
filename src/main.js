import './style.css';

const status = document.getElementById('status');
const checks = [];

if (window.crypto && window.crypto.getRandomValues) {
  const probe = new Uint8Array(8);
  window.crypto.getRandomValues(probe);
  checks.push(`csprng ok (${Array.from(probe).map(b => b.toString(16).padStart(2, '0')).join('')})`);
} else {
  checks.push('csprng MISSING');
}

if (window.crypto && window.crypto.subtle) {
  checks.push('webcrypto subtle ok');
} else {
  checks.push('webcrypto subtle MISSING');
}

checks.push(`ua: ${navigator.userAgent.slice(0, 60)}`);
status.textContent = checks.join(' · ');