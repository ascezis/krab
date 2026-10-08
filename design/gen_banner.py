#!/usr/bin/env python3
"""Генератор баннера krab: пиксельный краб (зеркалится из левой половины)
в рамке. Запуск: python3 gen_banner.py

Идея: рисуем только ЛЕВУЮ половину краба решёткой из '#' и '.', скрипт зеркалит
её (симметрия гарантирована) и сворачивает два пиксельных ряда в один текстовый
через полублоки ▀ ▄ █. Так краб получается ровным, а не нарисованным на глаз.
"""

# Левая половина краба. Последний столбец = центральная ось.
# '#' пиксель закрашен, '.' пусто. Все строки ОДИНАКОВОЙ длины.
CRAB_LEFT = [
    "..###..#....",  # верх клешни + глаз на стебельке
    ".#...#.#....",
    ".#...#.#....",
    "..##.#######",  # клешня сходится с телом
    "....########",
    "...#########",
    "....########",
    ".....#######",
    "....#.#.#.#.",  # ножки
    "...#..#..#.#",
]

TITLE = "krab  v0.1.0"
TAGLINE = "локальное хранилище секретов"
INNER = 46  # ширина содержимого рамки в символах


def mirror(rows):
    assert len({len(r) for r in rows}) == 1, "строки разной длины"
    # r[-2::-1] = всё кроме центрального столбца, в обратном порядке
    return [r + r[-2::-1] for r in rows]


def to_blocks(grid):
    """Два пиксельных ряда -> один текстовый ряд из ▀ ▄ █."""
    if len(grid) % 2:
        grid = grid + ["." * len(grid[0])]
    out = []
    for y in range(0, len(grid), 2):
        line = ""
        for top, bottom in zip(grid[y], grid[y + 1]):
            t, b = top == "#", bottom == "#"
            line += "█" if t and b else "▀" if t else "▄" if b else " "
        out.append(line.rstrip())
    return out


def boxed(lines):
    pad = lambda s: s + " " * (INNER - len(s))
    row = lambda s="": "│ " + pad(s) + " │"
    out = ["╭" + "─" * (INNER + 2) + "╮"]
    out += [row(" " + l) for l in lines]  # +1 пробел: краб чуть отступает от рамки
    out += [row(), row(TITLE), row(TAGLINE)]
    out.append("╰" + "─" * (INNER + 2) + "╯")
    return out


if __name__ == "__main__":
    crab = to_blocks(mirror(CRAB_LEFT))
    print("\n".join(boxed(crab)))
    print()
    print("// Строки краба для Rust (const CRAB):")
    for l in crab:
        print(f'    "{l}",')
