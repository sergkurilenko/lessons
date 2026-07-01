// Данные школы «Ракурс» — из базы знаний (Документ 1: о школе, курсы и цены).
// Тарифы: «Сам», «С разбором», «Личный». Цены за курс целиком, в рублях.

const courses = [
  {
    name: "Телефон как камера",
    duration: "4 недели",
    level: "с нуля",
    about: "Свет, композиция, ракурс и обработка прямо в телефоне.",
    prices: { sam: 4900, razbor: 7900, lichny: 14900 },
  },
  {
    name: "Первая камера",
    duration: "6 недель",
    level: "базовый",
    about: "Выдержка, диафрагма, ISO — как перестать снимать в авто-режиме.",
    prices: { sam: 6900, razbor: 10900, lichny: 19900 },
  },
  {
    name: "Обработка без перегруза",
    duration: "3 недели",
    level: "любой",
    about: "Лёгкая обработка в Lightroom Mobile и на компьютере.",
    prices: { sam: 3900, razbor: 6400, lichny: 11900 },
  },
  {
    name: "Контент для соцсетей",
    duration: "4 недели",
    level: "базовый",
    about: "Съёмка и тексты для Telegram и VK: посты, истории, рубрики.",
    prices: { sam: 5900, razbor: 8900, lichny: 16900 },
  },
];

const tariffs = [
  {
    name: "Сам",
    about: "Все уроки и задания, доступ к чату потока. Без проверки домашних заданий.",
    featured: false,
  },
  {
    name: "С разбором",
    about: "Всё из «Сам» + проверка домашних заданий, письменная обратная связь по твоим кадрам и сертификат.",
    featured: true,
  },
  {
    name: "Личный",
    about: "Всё из «С разбором» + три индивидуальные видео-консультации с преподавателем.",
    featured: false,
  },
];

const rub = (n) => n.toLocaleString("ru-RU") + " ₽";

// Карточки курсов
document.getElementById("courses-grid").innerHTML = courses
  .map(
    (c) => `
    <article class="card">
      <div class="card-meta">
        <span class="tag">${c.duration}</span>
        <span class="tag tag-level">${c.level}</span>
      </div>
      <h3>${c.name}</h3>
      <p>${c.about}</p>
      <div class="card-price"><span>от</span> <b>${rub(c.prices.sam)}</b></div>
      <button type="button" class="fav-toggle" aria-pressed="false" data-course="${c.name}">
        <span class="star">☆</span><span class="fav-label">В избранное</span>
      </button>
    </article>`
  )
  .join("");

// Карточки тарифов
document.getElementById("tariffs-grid").innerHTML = tariffs
  .map(
    (t) => `
    <div class="tariff${t.featured ? " featured" : ""}">
      <h3>${t.name}</h3>
      <p>${t.about}</p>
    </div>`
  )
  .join("");

// Подсветка активного пункта меню при переходе в другой раздел (scroll-spy)
const navLinks = Array.from(document.querySelectorAll('.nav a[href^="#"]'));
const sections = navLinks
  .map((a) => document.querySelector(a.getAttribute("href")))
  .filter(Boolean);

const setActive = (id) => {
  navLinks.forEach((a) =>
    a.classList.toggle("active", a.getAttribute("href") === "#" + id)
  );
};

// Активен последний раздел, чей верх ушёл под шапку. Отдельно ловим низ
// страницы: короткий последний раздел (Контакты) иначе не успевает подняться
// в зону активности и подсветка на нём не срабатывает.
const LINE = 80; // px под шапкой
let ticking = false;

function updateActive() {
  ticking = false;
  const scrolledToBottom =
    window.innerHeight + Math.ceil(window.scrollY) >=
    document.documentElement.scrollHeight - 2;

  let currentId = null;
  if (scrolledToBottom) {
    currentId = sections[sections.length - 1].id;
  } else {
    for (const s of sections) {
      if (s.getBoundingClientRect().top <= LINE) currentId = s.id;
    }
  }
  setActive(currentId);
}

function requestUpdate() {
  if (ticking) return;
  ticking = true;
  requestAnimationFrame(updateActive);
}

window.addEventListener("scroll", requestUpdate, { passive: true });
window.addEventListener("resize", requestUpdate);
updateActive();

// Таблица цен
document.getElementById("price-table").innerHTML = `
  <thead>
    <tr>
      <th>Курс</th>
      <th>Сам</th>
      <th>С разбором</th>
      <th>Личный</th>
    </tr>
  </thead>
  <tbody>
    ${courses
      .map(
        (c) => `
      <tr>
        <td class="course-name">${c.name}</td>
        <td class="price">${rub(c.prices.sam)}</td>
        <td class="price hot">${rub(c.prices.razbor)}</td>
        <td class="price">${rub(c.prices.lichny)}</td>
      </tr>`
      )
      .join("")}
  </tbody>`;

// Избранные курсы: сохраняем выбор в localStorage
const FAV_KEY = "rakurs-fav";
const loadFavs = () => {
  try {
    return new Set(JSON.parse(localStorage.getItem(FAV_KEY)) || []);
  } catch {
    return new Set();
  }
};
const favs = loadFavs();

const favCount = document.getElementById("fav-count");
const updateCount = () => {
  favCount.textContent = favs.size;
  favCount.hidden = favs.size === 0;
};

const renderToggle = (btn) => {
  const on = favs.has(btn.dataset.course);
  btn.setAttribute("aria-pressed", String(on));
  btn.querySelector(".star").textContent = on ? "★" : "☆";
  btn.querySelector(".fav-label").textContent = on ? "В избранном" : "В избранное";
  btn.closest(".card").classList.toggle("is-fav", on);
};

document.querySelectorAll(".fav-toggle").forEach((btn) => {
  renderToggle(btn);
  btn.addEventListener("click", () => {
    const name = btn.dataset.course;
    favs.has(name) ? favs.delete(name) : favs.add(name);
    localStorage.setItem(FAV_KEY, JSON.stringify([...favs]));
    renderToggle(btn);
    updateCount();
  });
});
updateCount();

// Кнопка «Выбрать курс» в шапке ведёт к списку курсов
document.getElementById("choose-btn").addEventListener("click", () => {
  document.getElementById("courses").scrollIntoView({ behavior: "smooth" });
});
