// Примеры кадров для видоискателя. Каждому фото — тег техники, EXIF и совет
// в голосе школы (на «ты», коротко, без пафоса).

const shots = [
  {
    src: "pics/1.jpg",
    tag: "СВЕТ",
    title: "Золотой час",
    tip: "Снимай на рассвете или закате — мягкий тёплый свет прощает почти всё.",
    exif: "35mm · f/8 · 1/125 · ISO 100",
  },
  {
    src: "pics/2.jpg",
    tag: "СВЕТ",
    title: "Контровый свет в тумане",
    tip: "Поставь солнце за объект — туман начинает светиться, а кадр обретает глубину.",
    exif: "85mm · f/4 · 1/500 · ISO 200",
  },
  {
    src: "pics/3.jpg",
    tag: "ВЫДЕРЖКА",
    title: "Заморозить движение",
    tip: "Короткая выдержка ловит каждую каплю. Здесь брызги застыли на 1/1000 секунды.",
    exif: "50mm · f/5.6 · 1/1000 · ISO 400",
  },
  {
    src: "pics/4.jpg",
    tag: "ISO",
    title: "Съёмка при слабом свете",
    tip: "Мало света — подними ISO и открой диафрагму. Немного шума лучше, чем смаз.",
    exif: "35mm · f/2.8 · 1/60 · ISO 3200",
  },
  {
    src: "pics/5.jpg",
    tag: "ФОКУС",
    title: "Портрет: фокус на глаза",
    tip: "В портрете резкими должны быть глаза. Открытая диафрагма размывает фон.",
    exif: "200mm · f/2.8 · 1/800 · ISO 200",
  },
];

const photo = document.getElementById("vf-photo");
const lightInput = document.getElementById("light");
const focusInput = document.getElementById("focus");
const lightVal = document.getElementById("light-val");
const focusVal = document.getElementById("focus-val");
const evEl = document.getElementById("vf-ev");
const afBox = document.getElementById("vf-af");
const focusStatus = document.getElementById("vf-focus-status");
const tagEl = document.getElementById("vf-tag");
const counterEl = document.getElementById("vf-counter");
const exifEl = document.getElementById("vf-exif");
const hudTitle = document.getElementById("vf-hud-title");
const shotTitle = document.getElementById("shot-title");
const shotTip = document.getElementById("shot-tip");
const thumbsEl = document.getElementById("thumbs");
const viewfinder = document.getElementById("viewfinder");

const pad = (n) => String(n).padStart(2, "0");
let index = 0;

// Миниатюры
thumbsEl.innerHTML = shots
  .map(
    (s, i) => `
    <button class="thumb" data-i="${i}" aria-label="${s.title}">
      <img src="${s.src}" alt="${s.title}">
    </button>`
  )
  .join("");
const thumbs = Array.from(thumbsEl.querySelectorAll(".thumb"));

function show(i) {
  index = (i + shots.length) % shots.length;
  const s = shots[index];
  photo.src = s.src;
  photo.alt = s.title;
  // перезапуск анимации проявления кадра
  photo.style.animation = "none";
  void photo.offsetWidth;
  photo.style.animation = "";
  tagEl.textContent = s.tag;
  counterEl.textContent = `${pad(index + 1)}/${pad(shots.length)}`;
  exifEl.textContent = s.exif;
  hudTitle.textContent = s.title;
  shotTitle.textContent = s.title;
  shotTip.textContent = s.tip;
  thumbs.forEach((t, ti) => t.classList.toggle("active", ti === index));
  applyFx(); // сохраняем текущие свет/фокус на новом кадре
}

// Интерактив: свет (экспозиция) и фокус меняют картинку через CSS-фильтры
const MAX_BLUR = 12; // px при полностью сбитом фокусе
const LOCK_AT = 90; // % фокуса, при котором наводка считается захваченной

function applyFx() {
  const light = Number(lightInput.value); // -100..100
  const focus = Number(focusInput.value); // 0..100

  const brightness = 1 + (light / 100) * 0.6; // 0.4..1.6
  const contrast = 1 + (light / 100) * 0.12;
  const blur = ((100 - focus) / 100) * MAX_BLUR;
  photo.style.filter = `brightness(${brightness.toFixed(3)}) contrast(${contrast.toFixed(
    3
  )}) blur(${blur.toFixed(2)}px)`;

  // Экспокоррекция в EV
  const ev = light / 50; // -2.0..+2.0
  const evText =
    (ev > 0 ? "+" : ev < 0 ? "−" : "±") + Math.abs(ev).toFixed(1) + " EV";
  evEl.textContent = evText;
  lightVal.textContent = evText;

  // Фокус
  focusVal.textContent = focus + "%";
  const locked = focus >= LOCK_AT;
  afBox.classList.toggle("locked", locked);
  focusStatus.classList.toggle("locked", locked);
  focusStatus.textContent = locked ? "● РЕЗКО" : "◌ ФОКУСИРОВКА";
}

lightInput.addEventListener("input", applyFx);
focusInput.addEventListener("input", applyFx);

// Клик по рамке AF — имитация автофокуса: короткий поиск и захват
afBox.addEventListener("click", () => {
  focusInput.value = 45;
  applyFx();
  setTimeout(() => {
    focusInput.value = 100;
    applyFx();
  }, 160);
});

const next = () => show(index + 1);
const prev = () => show(index - 1);

document.getElementById("vf-next").addEventListener("click", next);
document.getElementById("vf-prev").addEventListener("click", prev);
thumbs.forEach((t) =>
  t.addEventListener("click", () => show(Number(t.dataset.i)))
);

// Листание стрелками с клавиатуры
viewfinder.addEventListener("keydown", (e) => {
  if (e.key === "ArrowRight") { next(); e.preventDefault(); }
  if (e.key === "ArrowLeft") { prev(); e.preventDefault(); }
});

show(0);
