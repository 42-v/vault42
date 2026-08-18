import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { defineComponent, h, ref } from 'vue'
import { useModalFocus } from '../composables/useModalFocus'

/**
 * A minimal dialog wired the way the three real ones are: `v-if` on a flag, the
 * dialog element carrying `ref="dialogRef"`, and Escape routed back through the
 * component's own close handler.
 */
const Harness = defineComponent({
  props: {
    withFocusables: { type: Boolean, default: true },
    /** Leaves dialogRef unbound, as a mis-wired dialog would. */
    bindRef: { type: Boolean, default: true },
  },
  setup(props, { expose }) {
    const open = ref(false)
    const { dialogRef } = useModalFocus(open, () => { open.value = false })
    expose({ closeNow: () => { open.value = false } })

    return () => [
      h('button', { id: 'trigger', onClick: () => { open.value = true } }, 'open'),
      h('button', { id: 'outside' }, 'outside'),
      open.value
        ? h('div', { ref: props.bindRef ? dialogRef : undefined, id: 'dialog', role: 'dialog' },
            props.withFocusables
              ? [
                  h('button', { id: 'first' }, 'first'),
                  h('input', { id: 'middle' }),
                  h('button', { id: 'last' }, 'last'),
                ]
              : [h('p', 'nothing focusable here')])
        : null,
    ]
  },
})

function key(name: string, shiftKey = false): KeyboardEvent {
  return new KeyboardEvent('keydown', { key: name, shiftKey, bubbles: true, cancelable: true })
}

function el(id: string): HTMLElement {
  const found = document.getElementById(id)
  if (!found) throw new Error(`#${id} is not in the document`)
  return found
}

let wrapper: ReturnType<typeof mount> | null = null

async function openDialog(withFocusables = true, bindRef = true) {
  wrapper = mount(Harness, { props: { withFocusables, bindRef }, attachTo: document.body })
  el('trigger').focus()
  await el('trigger').dispatchEvent(new MouseEvent('click', { bubbles: true }))
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  document.body.innerHTML = ''
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

describe('useModalFocus', () => {
  it('moves focus into the dialog when it opens', async () => {
    // Before this, no .focus() call existed anywhere in the app: the dialog
    // opened with focus still on the trigger behind the overlay.
    await openDialog()
    expect(document.activeElement?.id).toBe('first')
  })

  it('cycles forward from the last element back to the first', async () => {
    await openDialog()
    el('last').focus()
    document.dispatchEvent(key('Tab'))

    expect(document.activeElement?.id).toBe('first')
  })

  it('cycles backward from the first element to the last', async () => {
    await openDialog()
    el('first').focus()
    document.dispatchEvent(key('Tab', true))

    expect(document.activeElement?.id).toBe('last')
  })

  it('leaves a tab between two inner elements to the browser', async () => {
    await openDialog()
    el('first').focus()
    const event = key('Tab')
    document.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(false)
    expect(document.activeElement?.id).toBe('first')
  })

  it('pulls focus back in when it has escaped to the page behind', async () => {
    await openDialog()
    el('outside').focus()
    document.dispatchEvent(key('Tab'))

    expect(document.activeElement?.id).toBe('first')
  })

  it('pulls focus back to the last element on a shift-tab from outside', async () => {
    await openDialog()
    el('outside').focus()
    document.dispatchEvent(key('Tab', true))

    expect(document.activeElement?.id).toBe('last')
  })

  it('swallows Tab in a dialog with nothing focusable rather than letting it out', async () => {
    await openDialog(false)
    const event = key('Tab')
    document.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(true)
  })

  it('closes on Escape', async () => {
    const w = await openDialog()
    const event = key('Escape')
    document.dispatchEvent(event)
    await flushPromises()

    expect(event.defaultPrevented).toBe(true)
    expect(w.find('#dialog').exists()).toBe(false)
  })

  it('restores focus to whatever opened it', async () => {
    // Without this the browser drops focus to <body> and the next Tab restarts
    // from the top of the page.
    await openDialog()
    document.dispatchEvent(key('Escape'))
    await flushPromises()

    expect(document.activeElement?.id).toBe('trigger')
  })

  it('ignores keys other than Tab and Escape', async () => {
    await openDialog()
    const event = key('a')
    document.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(false)
    expect(document.activeElement?.id).toBe('first')
  })

  it('stops listening once the dialog is closed', async () => {
    await openDialog()
    document.dispatchEvent(key('Escape'))
    await flushPromises()

    el('outside').focus()
    const event = key('Tab')
    document.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(false)
    expect(document.activeElement?.id).toBe('outside')
  })

  it('swallows Tab when the dialog element was never bound', async () => {
    // Defensive: an unbound ref means the trap has nothing to search, and
    // letting Tab through would drop the user behind the overlay.
    await openDialog(true, false)
    const event = key('Tab')
    document.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(true)
  })

  it('ignores a key pressed in the same tick the dialog was closed', async () => {
    // The watcher that detaches the listener flushes pre-render, so there is a
    // window where the flag is already false and the listener is still live.
    const w = await openDialog()
    ;(w.vm as unknown as { closeNow: () => void }).closeNow()

    const event = key('Tab')
    document.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(false)
    await flushPromises()
  })

  it('stops listening when the component goes away with the dialog still open', async () => {
    const w = await openDialog()
    w.unmount()
    wrapper = null

    const event = key('Escape')
    document.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(false)
  })
})
