# Дизайн-система «Ночной атлас» — что уже есть в коде

Не создавайте новых цветов, шрифтов и отступов: берите из этого списка. Если чего-то не хватает, опишите в PR, дизайнер добавит.

## Токены (`:root`, тёмная тема; светлая переопределяет в `:root[data-theme="light"]`)
| Токен | Тёмная | Светлая | Назначение |
|---|---|---|---|
| `--bg` | #0c0b14 | #f4f3fa | фон страницы |
| `--text` / `--muted` / `--dim` | #ecebf5 / #a3a1ba / #8d8ba6 | #17152b / #5a5873 | текст основной / вторичный / третичный |
| `--accent` / `--accent2` / `--accent-ink` | #a99bff / #c4b9ff / #14102b | #5b45e0 / … / #fff | акцент, hover, текст на акценте |
| `--green` / `--yellow` / `--red` | #6ee7a8 / #fbbf5b / #ff8f8f | #0b7a47 / #8a5a00 / #b42318 | успех / внимание / ошибка |
| `--glass` / `--glass2` / `--border` / `--border2` | полупрозрачные белые | светлые аналоги | поверхности и линии |
| `--field`, `--field-b` | поля ввода | | |
| `--nav-h` | 60px | | высота навбара (использовать в `calc`) |
| `--font`, `--font-d` | Geologica, Unbounded | | текст и заголовки/главные кнопки |
| `--r-s` / `--r-m` / `--r-l` | 12 / 18 / 22px | | радиусы |

## Готовые классы
- Поверхности: `.glass`, `.glass2`. Страница: `.page`, `.section-header`, `.section-title`, `.chips`.
- Кнопки: `.btn` + `.btn-primary` | `.btn-ghost` | `.btn-danger`, размер `.btn-sm`. Главное действие на экране — одна `.btn-primary`.
- Бейджи: `.badge` + `.badge-dot` + `.badge-green|yellow|red|blue|dim`. Прогресс: `.progress` / `.progress-bar`. Переключатель: `.sw` (`role="switch"`, `aria-checked`).
- Меню «⋯»: `.menuwrap` > кнопка `.icon-btn` + `.menu` (`toggleMenu(btn, ev)`, `closeMenus(null)` уже есть). Опасный пункт — `.danger`.
- Карточки предметов: `.card-grid`, `.subject-card`, `.card-top`, `.card-title`, `.card-meta`.
- Источники: `.source-item`, `.source-icon`, `.source-info`, `.source-actions`, `.drop-zone`.
- Билеты: `.ticket-add`, `.ticket-item`, `.ticket-head`, `.ticket-q`, `.ticket-answer`. Чат: `.chat-shell`, `.conv-sidebar`, `.msg*`, `.chat-scope`.
- Прочее: `.empty` (иконка + `<b>` + `<span>`), `.tabs`/`.tab`, `.modal-overlay` + `.modal` (`.wide`), `.toast`, `.prov` (ссылка на источник; в задаче 05 превращается в чип).
- Помощники JS: `ic(IC.name, size, filled)` — иконки; `plural(n, [один, два, пять])`; `esc()`; `setTheme()`; `toast(msg, type)`.

## Правила
- Только токены, обе темы. Цели нажатия ≥ 44 px. Фокус виден (`:focus-visible`).
- Safari: `-webkit-backdrop-filter`, без `inset`, `dvh` с запасным `vh`.
- Брейкпоинты: ≤ 480, ≤ 768 (телефон/планшет в портрете), ≥ 1024 (две колонки).
- Анимации короткие и отключаются при `prefers-reduced-motion`.
- Экран-образец (как должно выглядеть): `docs/ux/ux-map.html`, раздел «Экраны».
