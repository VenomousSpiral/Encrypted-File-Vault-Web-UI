# Player Navigation Improvements — Feature Specification

## Overview

The player page's prev/next/shuffle navigation needs three core improvements:
1. **Visit-history tracking** so "go back" returns to the previously viewed file, not just whatever is sorted before it.
2. **Sort-order fidelity** so next/prev always follow whichever sort mode is active (name / recent / added / size).
3. **Recursive vs current-dir toggle** visible in the player UI for controlling whether navigation spans subdirectories.

---

## 1. Visit-History Stack (Go Back)

### Current Problem
When pressing Previous, the code looks up `siblingData.prev_id` — a file that happens to be sorted before the current one. It does **not** remember which file you actually came from. If File A → Next → File B → Prev, it should return to A; instead it may land on some other file C if sort order has changed or files were added/removed.

### New Behavior
- Maintain a **visit history stack** (in-memory array) in the player page JavaScript.
- Every time a new file is loaded via navigation (`navigateTo()`), push the previous file's ID onto the stack before leaving it.
- The "Previous" button navigates to `history[stack.length - 1]` and pops that entry — i.e., **returns you to whichever file was actually displayed last**.
- This works independently of sort order or shuffle mode.

### Shuffle History (Separate)
Shuffle gets its own independent history stack:
- When shuffle is ON, pressing Previous returns to the previously shuffled-to file (via shuffle's history), not via sort order.
- When you switch from shuffle OFF → shuffle ON, navigation uses sort-order; when ON → OFF, it resumes using sort-order prev/next.
- The two histories are separate: switching modes doesn't corrupt either stack.

---

## 2. Sort-Order Navigation (Next / Previous)

### Rule
When **shuffle is OFF**, the Next and Previous buttons follow the current sort preference strictly among same-type files.

| Sort Mode | Next Button Goes To… |
|-----------|----------------------|
| Name      | Next file alphabetically in sorted list |
| Recent    | File with earlier last-accessed timestamp |
| Added     | File created just before current one |
| Size      | Smaller (or larger) same-type file depending on sort direction |

### How It Works
1. The API endpoint `/api/siblings/<file_id>` accepts `?sort_by=` and `?recurse=` query params.
2. When shuffle is OFF, the player passes the **current active sort preference** to this endpoint (from localStorage or user settings).
3. The server returns `prev_id` / `next_id` based on that exact sort order within same-type files.
4. Shuffle mode bypasses prev/next entirely and calls `/api/random-sibling/<file_id>` instead, using the visit-history stack for "go back" behavior.

### Sort Preference Propagation
- The explorer page stores a user preference (`sort_preference`) via POST to `/api/preferences`.
- This preference is read on the player page (via `get_user_preferences` or localStorage) and passed as `?sort_by=` in every siblings API call when shuffle is OFF.
- Changing sort order while viewing a file updates prev/next immediately — no reload needed.

---

## 3. Recursive / Current-Dir Toggle Button

### New UI Element
Add a toggle button to the player's top bar (between the Next/Shuffle buttons and Download):

```
[←] [< 5 / 12>] [→] [🔀 Shuffle] [⊞ Recursive | ⊟ Current Dir Only] [↓ Download]
```

- Button text/icon toggles between: **Recursive** (icon: folders) and **Current Dir Only** (icon: folder).
- Active state is visually highlighted when recursive mode is on.
- State persists in `localStorage` so it survives page reloads and navigation.

### Behavior When Recursive = ON
- Navigation spans the entire directory tree rooted at your browsing origin point (`?from=` parameter or stored root parent ID).
- All same-type files across all subdirectories are collected, sorted by current preference, then prev/next walks that full list.
- Example: If sorted by size and recursive is on, pressing Next goes to the next-largest file anywhere in this directory tree (current folder + every subdir recursively).

### Behavior When Recursive = OFF
- Navigation only considers same-type files in the **immediate parent folder** of the currently viewed file.
- Subdirectories are ignored entirely — no files from subdirs appear in prev/next.

### API Integration
The toggle passes `?recurse=1` or `?recurse=0` to `/api/siblings/<file_id>`:
```
/api/siblings/{id}?sort_by=size&recurse=1   → recursive mode
/api/siblings/{id}?sort_by=name&recurse=0   → current dir only
```

The random-sibling endpoint (`/api/random-sibling`) also respects this via the `root` parameter for shuffle-mode navigation.

---

## 4. Shuffle Mode — Independent Navigation Rules

### Behavior When Shuffle = ON
- Pressing Next calls `/api/random-sibling/<file_id>` to get a **random** same-type file from the root directory tree (not sequential in any sort order).
- The "Previous" button uses shuffle's own visit-history stack: it returns you to whichever file was displayed *before* the current one during this shuffle session.

### Shuffle + Recursive Interaction
- When recursive is ON, random selection spans all same-type files across subdirectories.
- When recursive is OFF, random selection only picks from same-type files in the immediate parent folder.

### Switching Between Modes
| Action | What Happens |
|--------|-------------|
| Shuffle OFF → Next | Goes to next file in sort order (prev/next stack) |
| Shuffle ON → Next   | Random file; pushed onto shuffle history stack |
| Shuffle ON → Prev   | Returns to previous shuffled-to file via shuffle history |
| Switch modes          | Each mode keeps its own independent history. No corruption. |

---

## 5. Position Counter Display

The `navPos` element (showing "X / Y") always reflects:
- **Recursive ON:** Total count of same-type files across the entire tree, current position in recursive sort order.
- **Recursive OFF:** Total count of same-type files in the immediate folder only, current position within that subset.

The counter updates live when sort order or recursion mode changes.

---

## Files Modified

| File | Change |
|------|--------|
| `templates/player.html` | Add recursive toggle button; add visit-history logic (shuffle stack + normal prev/next stack); update navigation functions (`goBack`, `navigateTo`, `loadSiblings`); read URL params for sort/recurse priority |
| `app.py` | Fix parameter name consistency (`sort_by` instead of `sort`); ensure `/api/siblings` returns correct total/position matching recursion mode; add recurse support to `/api/random-sibling`; exclude current file from random selection |
| `static/js/app.js` | Pass sort preference and recursion state when navigating to player/editor/cbz pages so settings carry over from explorer |

---

## Edge Cases Handled

1. **No next file:** Disable the Next button (already done).
2. **Switching sort while viewing a file:** Re-fetch siblings with new sort; update prev/next immediately without reload.
3. **Shuffle picks same file as current:** API should exclude current file from random selection (existing behavior — verify).
4. **Empty folder / no sibling files of same type:** Show position "0 / 0", disable both nav buttons.
5. **File deleted during viewing:** The siblings endpoint returns prev/next based on what still exists; if current file is gone, show error or navigate to adjacent file.
