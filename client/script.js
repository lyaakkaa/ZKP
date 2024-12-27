// ------------------------------------------------
// Пример функции для SHA-256 (используем SubtleCrypto)
// Возвращаем hex-строку.
async function hashPassword(password) {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hexString = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hexString;
}

// Преобразовать hex → BigInt → по модулю (p-1).
function passwordToX(hexHash, pMinus1) {
  let x = BigInt("0x" + hexHash);
  x = x % pMinus1;
  if (x === 0n) x = 1n;
  return x;
}

// Быстрая функция бинарной экспоненциации на BigInt
function modExp(base, exp, mod) {
  let result = 1n;
  let cur = base % mod;
  let e = exp;
  while (e > 0) {
    if (e & 1n) {
      result = (result * cur) % mod;
    }
    cur = (cur * cur) % mod;
    e >>= 1n;
  }
  return result;
}

// Генерация псевдослучайного BigInt
function randomBigInt(max) {
  // Упрощённо, получаем 32-бит случайное
  const rand32 = BigInt(Math.floor(Math.random() * 0xffffffff));
  return (rand32 % (max - 1n)) + 1n;
}

// ------------------------------------------------
// 1) Registration
// ------------------------------------------------
const regForm = document.getElementById("regForm");
const regResultDiv = document.getElementById("regResult");

regForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("regUser").value;
  const password = document.getElementById("regPass").value;

  try {
    const res = await fetch("http://127.0.0.1:5000/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (res.ok) {
      regResultDiv.textContent = data.message + ` (p=${data.p}, g=${data.g})`;
    } else {
      regResultDiv.textContent = `Error: ${data.error}`;
    }
  } catch (err) {
    regResultDiv.textContent = `Fetch error: ${err}`;
  }
});

// ------------------------------------------------
// 2) Login
// ------------------------------------------------
const loginForm = document.getElementById("loginForm");
const loginResultDiv = document.getElementById("loginResult");

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  loginResultDiv.textContent = "";

  const username = document.getElementById("loginUser").value;
  const password = document.getElementById("loginPass").value;

  try {
    // Шаг a) /login/start
    let res = await fetch("http://127.0.0.1:5000/login/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    let data = await res.json();
    if (!res.ok) {
      loginResultDiv.textContent = `Error: ${data.error}`;
      return;
    }

    // Из ответа берем p, g, h, e
    const p = BigInt(data.p);
    const g = BigInt(data.g);
    const h = BigInt(data.h);
    const eVal = BigInt(data.e);

    // Считаем x (хэш пароля) -> BigInt -> mod (p-1)
    const hexHash = await hashPassword(password);
    const x = passwordToX(hexHash, p - 1n);

    // Генерируем r, считаем a = g^r mod p
    const r = randomBigInt(p - 1n);
    const a = modExp(g, r, p);

    // y = r + e*x (mod p-1)
    const y = (r + eVal * x) % (p - 1n);

    // Шаг b) /login/finish
    res = await fetch("http://127.0.0.1:5000/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        a: a.toString(),
        y: y.toString(),
      }),
      credentials: "include",
    });
    data = await res.json();
    if (res.ok) {
      loginResultDiv.textContent = data.message; // "Login successful!"
    } else {
      loginResultDiv.textContent = `Error: ${data.error}`;
    }
  } catch (err) {
    loginResultDiv.textContent = `Fetch error: ${err}`;
  }
});

// ------------------------------------------------
// 3) Protected
// ------------------------------------------------
const btnProtected = document.getElementById("btnProtected");
const protectedResultDiv = document.getElementById("protectedResult");

btnProtected.addEventListener("click", async () => {
  try {
    const res = await fetch("http://127.0.0.1:5000/protected", {
      method: "GET",
      credentials: "include",
    });
    const data = await res.json();
    if (res.ok) {
      protectedResultDiv.textContent = data.message;
    } else {
      protectedResultDiv.textContent = `Error: ${data.error}`;
    }
  } catch (err) {
    protectedResultDiv.textContent = `Fetch error: ${err}`;
  }
});

const btnLogout = document.getElementById("btnLogout");

btnLogout.addEventListener("click", async () => {
  try {
    const res = await fetch("http://127.0.0.1:5000/logout", {
      method: "POST",
      credentials: "include", // Include session cookies
    });
    if (res.ok) {
    } else {
      const data = await res.json();
      alert(`Error: ${data.error}`);
    }
  } catch (err) {
    alert(`Fetch error: ${err}`);
  }
});
