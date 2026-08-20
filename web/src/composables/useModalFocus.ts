import { nextTick, onBeforeUnmount, watch, type Ref, type ShallowRef } from 'vue'

/**
 * Elements a browser will move focus to with Tab.
 *
 * `[tabindex="-1"]` is excluded deliberately: it is programmatically focusable
 * but not part of the tab order, and treating it as a stop would make the trap
 * disagree with the browser about where the cycle ends.
 */
const FOCUSABLE = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

/**
 * Any ref that yields the dialog element, whether from `useTemplateRef` (which
 * is read-only and shallow) or from a plain `ref` in a test harness.
 *
 * The composable only ever reads it, so accepting the read-only shape as well
 * costs nothing and is what lets a component keep ownership of its own element
 * ref rather than receive one it then has to bind by name.
 */
export type DialogElementRef =
  | Ref<HTMLElement | null>
  | Readonly<ShallowRef<HTMLElement | null>>

/**
 * Traps focus inside an open dialog, restores it on close, and closes on Escape.
 *
 * None of this existed. The app contained no `.focus()` call at all, so all
 * three dialogs — delete file, delete identity, and the password
 * re-authentication that guards every 2FA change — opened with focus still on
 * the trigger behind the overlay. Tab walked straight out into the page the
 * overlay was covering, Escape did nothing, and closing the dialog dropped focus
 * to `<body>`, sending a keyboard user back to the top of the document with no
 * announcement. On the 2FA dialog that is a password field a screen-reader user
 * could not reach without hunting for it.
 *
 * The listener is registered on `document` in the capture phase so it sees
 * Escape and Tab before anything inside the dialog can stop them, and it is
 * scoped to the open state so a closed dialog costs nothing.
 *
 * The component owns the element ref and hands it in. It used to be the other
 * way round: the composable created the ref, returned it, and the template
 * bound it by name with `ref="dialogRef"`. That left the component holding a
 * value it never mentioned again, joined to the element only by a string
 * happening to match a variable, and nothing checked the match.
 *
 * `useTemplateRef` closes that. Called without a type argument it resolves the
 * name against the template, so a misspelling is a compile error naming the
 * refs that do exist, and the element type is inferred from the tag rather
 * than asserted. Supplying the type argument turns both off, which is why
 * these call sites do not.
 *
 * @param isOpen - Reactive open state. The dialog is expected to be `v-if`-ed on it.
 * @param close - Called when the user presses Escape. Should flip `isOpen` false.
 * @param dialogRef - Ref to the dialog element, from `useTemplateRef`.
 *
 * @example
 * ```ts
 * const dialogRef = useTemplateRef('dialog')
 * useModalFocus(showDeleteConfirm, () => { showDeleteConfirm.value = false }, dialogRef)
 * ```
 * ```vue
 * <div v-if="showDeleteConfirm" ref="dialog" role="dialog" aria-modal="true">
 * ```
 */
export function useModalFocus(
  isOpen: Ref<boolean | unknown>,
  close: () => void,
  dialogRef: DialogElementRef,
): void {
  let restoreTo: HTMLElement | null = null

  function focusableItems(): HTMLElement[] {
    const root = dialogRef.value
    return root ? Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)) : []
  }

  function onKeydown(event: KeyboardEvent): void {
    // The watcher below detaches this listener on close, but it runs on the
    // pre-flush tick: a key pressed in the same tick as the flag flipping would
    // otherwise still be handled by a dialog that is on its way out.
    if (!isOpen.value) return

    if (event.key === 'Escape') {
      event.preventDefault()
      close()
      return
    }

    if (event.key !== 'Tab') return

    const items = focusableItems()
    if (items.length === 0) {
      // Nothing to land on, but Tab must still not escape the dialog.
      event.preventDefault()
      return
    }

    const first = items[0]
    const last = items[items.length - 1]
    // -1 for anything not in the dialog, which includes focus having escaped to
    // the page behind the overlay and `activeElement` being null outright.
    const index = items.indexOf(document.activeElement as HTMLElement)

    if (event.shiftKey) {
      if (index <= 0) {
        event.preventDefault()
        last.focus()
      }
      return
    }

    if (index === -1 || index === items.length - 1) {
      event.preventDefault()
      first.focus()
    }
  }

  function detach(): void {
    document.removeEventListener('keydown', onKeydown, true)
  }

  watch(
    () => Boolean(isOpen.value),
    async (open) => {
      if (open) {
        restoreTo = document.activeElement as HTMLElement | null
        document.addEventListener('keydown', onKeydown, true)
        // The dialog is rendered by v-if, so it does not exist yet on the tick
        // the flag flips.
        await nextTick()
        focusableItems()[0]?.focus()
        return
      }

      detach()
      // Back to whatever opened the dialog. Without this the browser drops focus
      // to <body> and the next Tab starts from the top of the page.
      restoreTo?.focus?.()
      restoreTo = null
    },
  )

  onBeforeUnmount(detach)
}
