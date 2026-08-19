import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent, h } from 'vue'
import BlobsView from '../views/BlobsView.vue'
import en from '../locales/en.json'

const mockFetchBlobs = vi.fn()
const mockUploadBlob = vi.fn()
const mockDownloadBlob = vi.fn()
const mockDeleteBlob = vi.fn()

const mockBlobs = ref<Array<{ id: string; label?: string; size_bytes: number; stored_bytes: number; checksum: string; created_at: string }>>([])
const mockQuota = ref<{ used_bytes: number; max_bytes: number; used_count: number; max_count: number } | null>(null)
const mockIsLoading = ref(false)
const mockIsUploading = ref(false)
const mockError = ref<{ code: string } | null>(null)
// Drives the VaultAuthGuard stub: true = auth session still resolving.
const mockGuardLoading = ref(false)

vi.mock('@vault42/vue', () => ({
  useBlobs: () => ({
    blobs: mockBlobs,
    quota: mockQuota,
    isLoading: mockIsLoading,
    isUploading: mockIsUploading,
    error: mockError,
    fetchBlobs: mockFetchBlobs,
    uploadBlob: mockUploadBlob,
    downloadBlob: mockDownloadBlob,
    deleteBlob: mockDeleteBlob,
  }),
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = (en as Record<string, string>)[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
    },
    formatDate: (d: Date) => d.toLocaleDateString(),
  }),
  VaultAuthGuard: defineComponent({
    setup(_, { slots }) {
      // Renders the loading slot while the session resolves, the default slot once authenticated.
      return () => {
        if (mockGuardLoading.value) return slots.loading ? slots.loading() : h('div')
        return slots.default ? slots.default() : h('div')
      }
    },
  }),
}))

function mountView() {
  return mount(BlobsView, {
    global: {
      stubs: {
        Teleport: true,
      },
    },
  })
}

// Intercepts the throwaway <a download> the view builds so the resulting filename can be asserted.
function captureDownload() {
  const anchor = { href: '', download: '', click: vi.fn() } as unknown as HTMLAnchorElement
  const originalCreateObjectURL = URL.createObjectURL
  const originalRevokeObjectURL = URL.revokeObjectURL
  URL.createObjectURL = vi.fn(() => 'blob:http://localhost/fake-url')
  URL.revokeObjectURL = vi.fn()

  const originalCreateElement = document.createElement.bind(document)
  const createSpy = vi.spyOn(document, 'createElement').mockImplementation((tag: string) =>
    tag === 'a' ? anchor : originalCreateElement(tag))
  const appendSpy = vi.spyOn(document.body, 'appendChild').mockImplementation(() => anchor as never)
  const removeSpy = vi.spyOn(document.body, 'removeChild').mockImplementation(() => anchor as never)

  return {
    anchor,
    restore() {
      URL.createObjectURL = originalCreateObjectURL
      URL.revokeObjectURL = originalRevokeObjectURL
      createSpy.mockRestore()
      appendSpy.mockRestore()
      removeSpy.mockRestore()
    },
  }
}

describe('BlobsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockBlobs.value = []
    mockQuota.value = null
    mockIsLoading.value = false
    mockIsUploading.value = false
    mockError.value = null
    mockGuardLoading.value = false
    mockFetchBlobs.mockResolvedValue(undefined)
    mockUploadBlob.mockResolvedValue(true)
    mockDownloadBlob.mockResolvedValue({ data: new ArrayBuffer(0) })
    mockDeleteBlob.mockResolvedValue(true)
  })

  it('renders the page title', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Encrypted Storage')
  })

  it('shows loading spinner when isLoading', () => {
    mockIsLoading.value = true
    const wrapper = mountView()
    expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
  })

  it('calls fetchBlobs on mount', () => {
    mountView()
    expect(mockFetchBlobs).toHaveBeenCalledOnce()
  })

  it('shows "No files stored yet" when blobs are empty', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('No files stored yet.')
  })

  it('renders blob list', () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1048576, stored_bytes: 800000, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
      { id: 'blob-2', label: 'image.png', size_bytes: 2097152, stored_bytes: 1500000, checksum: 'sha256:def', created_at: '2026-02-24T11:00:00Z' },
    ]
    const wrapper = mountView()

    expect(wrapper.text()).toContain('doc.pdf')
    expect(wrapper.text()).toContain('image.png')
    expect(wrapper.text()).not.toContain('No files stored yet.')
  })

  it('shows blob ID when no label', () => {
    mockBlobs.value = [
      { id: 'blob-no-label', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()
    expect(wrapper.text()).toContain('blob-no-label')
  })

  it('renders quota bar when quota is set', () => {
    mockQuota.value = { used_bytes: 5242880, max_bytes: 10485760, used_count: 3, max_count: 50 }
    const wrapper = mountView()

    expect(wrapper.text()).toContain('3 / 50 files')
    expect(wrapper.text()).toContain('5 MB')
    expect(wrapper.text()).toContain('10 MB')
  })

  it('renders upload form', () => {
    const wrapper = mountView()
    expect(wrapper.find('input[type="file"]').exists()).toBe(true)
    expect(wrapper.find('input[placeholder="my-document.pdf"]').exists()).toBe(true)
    expect(wrapper.find('button[type="submit"]').text()).toContain('Upload')
  })

  it('disables upload button when isUploading', () => {
    mockIsUploading.value = true
    const wrapper = mountView()
    const btn = wrapper.find('button[type="submit"]')
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
  })

  it('shows spinner during upload', () => {
    mockIsUploading.value = true
    const wrapper = mountView()
    const btn = wrapper.find('button[type="submit"]')
    expect(btn.find('.vault42-spinner').exists()).toBe(true)
  })

  it('renders download button for each blob', () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()
    const downloadBtns = wrapper.findAll('button').filter(b => b.text() === 'Download')
    expect(downloadBtns).toHaveLength(1)
  })

  it('renders delete button for each blob', () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()
    const deleteBtns = wrapper.findAll('button').filter(b => b.text() === 'Delete')
    expect(deleteBtns.length).toBeGreaterThanOrEqual(1)
  })

  it('shows error message when error exists', () => {
    mockError.value = { code: 'quota_exceeded' }
    const wrapper = mountView()
    expect(wrapper.find('.vault42-alert-error').text()).toBe('Storage quota exceeded.')
  })

  it('formats bytes correctly', () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'tiny.bin', size_bytes: 0, stored_bytes: 0, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockQuota.value = { used_bytes: 0, max_bytes: 10485760, used_count: 1, max_count: 50 }
    const wrapper = mountView()
    expect(wrapper.text()).toContain('0 B')
  })

  it('renders section headers', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('Upload File')
    expect(wrapper.text()).toContain('Your Files')
  })

  it('shows file label input with maxlength', () => {
    const wrapper = mountView()
    const labelInput = wrapper.find('input[placeholder="my-document.pdf"]')
    expect(labelInput.attributes('maxlength')).toBe('255')
  })

  it('calls deleteBlob when delete is confirmed', async () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()

    // Click Delete button on the blob row
    const deleteBtns = wrapper.findAll('button').filter(b => b.text() === 'Delete')
    await deleteBtns[0].trigger('click')

    // Now confirmation modal should show
    expect(wrapper.text()).toContain('Delete File')
    expect(wrapper.text()).toContain('permanently delete this encrypted file')

    // Find and click the confirm Delete button (vault42-btn-danger inside modal)
    const dangerBtns = wrapper.findAll('button').filter(b => b.classes().some(c => c.includes('vault42-btn-danger')))
    // The last danger button should be the modal confirm
    const confirmBtn = dangerBtns[dangerBtns.length - 1]
    await confirmBtn.trigger('click')
    await flushPromises()

    expect(mockDeleteBlob).toHaveBeenCalledWith('blob-1')
  })

  it('shows cancel button in delete modal', async () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()

    // Open delete modal
    const deleteBtns = wrapper.findAll('button').filter(b => b.text() === 'Delete')
    await deleteBtns[0].trigger('click')

    // Cancel button should exist
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    expect(cancelBtn).toBeDefined()
  })

  it('formats file sizes in blob list', () => {
    mockBlobs.value = [
      { id: 'b1', label: 'small.bin', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
      { id: 'b2', label: 'medium.bin', size_bytes: 1048576, stored_bytes: 800000, checksum: 'sha256:def', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()
    expect(wrapper.text()).toContain('1 KB')
    expect(wrapper.text()).toContain('1 MB')
  })

  it('shows dates in blob list', () => {
    mockBlobs.value = [
      { id: 'b1', label: 'test.bin', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()
    // Should contain at least year 2026
    expect(wrapper.text()).toContain('2026')
  })

  it('shows quota percentage via progress bar', () => {
    mockQuota.value = { used_bytes: 5242880, max_bytes: 10485760, used_count: 3, max_count: 50 }
    const wrapper = mountView()
    // Progress bar should have 50% width
    const progressBar = wrapper.find('[style]')
    expect(progressBar.attributes('style')).toContain('50%')
  })

  it('applies red color to quota bar when over 90%', () => {
    mockQuota.value = { used_bytes: 9961472, max_bytes: 10485760, used_count: 45, max_count: 50 }
    const wrapper = mountView()
    const progressBar = wrapper.findAll('div').find(d => d.classes().includes('h-2') && d.classes().includes('rounded-full') && d.attributes('style'))
    expect(progressBar?.classes()).toContain('bg-vault42-error')
  })

  it('applies primary color to quota bar when under 90%', () => {
    mockQuota.value = { used_bytes: 1048576, max_bytes: 10485760, used_count: 1, max_count: 50 }
    const wrapper = mountView()
    const progressBar = wrapper.findAll('div').find(d => d.classes().includes('h-2') && d.classes().includes('rounded-full') && d.attributes('style'))
    expect(progressBar?.classes()).toContain('bg-vault42-accent')
  })

  it('does not show quota bar when quota is null', () => {
    mockQuota.value = null
    const wrapper = mountView()
    // Quota bar shows "X / Y files" pattern — check it's absent
    expect(wrapper.text()).not.toMatch(/\d+ \/ \d+ files/)
  })

  it('has file input marked as required', () => {
    const wrapper = mountView()
    const fileInput = wrapper.find('input[type="file"]')
    expect(fileInput.attributes('required')).toBeDefined()
  })

  it('renders both Download and Delete for each blob', () => {
    mockBlobs.value = [
      { id: 'b1', label: 'a.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
      { id: 'b2', label: 'b.pdf', size_bytes: 2048, stored_bytes: 1600, checksum: 'sha256:def', created_at: '2026-02-24T11:00:00Z' },
    ]
    const wrapper = mountView()
    const downloadBtns = wrapper.findAll('button').filter(b => b.text() === 'Download')
    const deleteBtns = wrapper.findAll('button').filter(b => b.text() === 'Delete')
    expect(downloadBtns).toHaveLength(2)
    expect(deleteBtns).toHaveLength(2)
  })

  it('calls uploadBlob on form submit with file', async () => {
    const wrapper = mountView()

    // Create a mock file
    const fileContent = new ArrayBuffer(100)
    const mockFile = new File([fileContent], 'test.pdf', { type: 'application/pdf' })
    Object.defineProperty(mockFile, 'arrayBuffer', {
      value: () => Promise.resolve(fileContent),
    })

    // Set the file on the input
    const fileInput = wrapper.find('input[type="file"]')
    const inputEl = fileInput.element as HTMLInputElement
    Object.defineProperty(inputEl, 'files', { value: [mockFile], writable: false })

    // Set label
    await wrapper.find('input[placeholder="my-document.pdf"]').setValue('my-label')

    // Submit form
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockUploadBlob).toHaveBeenCalledWith(fileContent, 'my-label')
  })

  it('uses filename as label when label input is empty', async () => {
    const wrapper = mountView()

    const fileContent = new ArrayBuffer(50)
    const mockFile = new File([fileContent], 'photo.png', { type: 'image/png' })
    Object.defineProperty(mockFile, 'arrayBuffer', {
      value: () => Promise.resolve(fileContent),
    })

    const fileInput = wrapper.find('input[type="file"]')
    const inputEl = fileInput.element as HTMLInputElement
    Object.defineProperty(inputEl, 'files', { value: [mockFile], writable: false })

    // Do NOT set label — should fall back to file.name
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockUploadBlob).toHaveBeenCalledWith(fileContent, 'photo.png')
  })

  it('does not upload when no file is selected', async () => {
    const wrapper = mountView()

    // Submit without selecting a file
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockUploadBlob).not.toHaveBeenCalled()
  })

  it('clears label input after successful upload', async () => {
    mockUploadBlob.mockResolvedValue(true)
    const wrapper = mountView()

    const fileContent = new ArrayBuffer(10)
    const mockFile = new File([fileContent], 'doc.txt')
    Object.defineProperty(mockFile, 'arrayBuffer', {
      value: () => Promise.resolve(fileContent),
    })

    const fileInput = wrapper.find('input[type="file"]')
    Object.defineProperty(fileInput.element, 'files', { value: [mockFile], writable: false })

    await wrapper.find('input[placeholder="my-document.pdf"]').setValue('my-doc')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect((wrapper.find('input[placeholder="my-document.pdf"]').element as HTMLInputElement).value).toBe('')
  })

  it('keeps the typed label when the upload fails so the user does not have to retype it', async () => {
    mockUploadBlob.mockResolvedValue(false)
    const wrapper = mountView()

    const fileContent = new ArrayBuffer(10)
    const mockFile = new File([fileContent], 'doc.txt')
    Object.defineProperty(mockFile, 'arrayBuffer', { value: () => Promise.resolve(fileContent) })
    Object.defineProperty(wrapper.find('input[type="file"]').element, 'files', { value: [mockFile], writable: false })

    await wrapper.find('input[placeholder="my-document.pdf"]').setValue('quarterly-report')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(mockUploadBlob).toHaveBeenCalledExactlyOnceWith(fileContent, 'quarterly-report')
    expect((wrapper.find('input[placeholder="my-document.pdf"]').element as HTMLInputElement).value).toBe('quarterly-report')
  })

  it('calls downloadBlob and creates anchor for download', async () => {
    mockBlobs.value = [
      { id: 'blob-dl', label: 'report.pdf', size_bytes: 2048, stored_bytes: 1500, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockDownloadBlob.mockResolvedValue({ data: new ArrayBuffer(100), label: 'report.pdf' })

    // Mock URL.createObjectURL and URL.revokeObjectURL
    const mockUrl = 'blob:http://localhost/fake-url'
    const originalCreateObjectURL = URL.createObjectURL
    const originalRevokeObjectURL = URL.revokeObjectURL
    URL.createObjectURL = vi.fn(() => mockUrl)
    URL.revokeObjectURL = vi.fn()

    // Mock document.createElement to capture the anchor
    const mockClick = vi.fn()
    const originalCreateElement = document.createElement.bind(document)
    const mockAnchor = { href: '', download: '', click: mockClick } as unknown as HTMLAnchorElement
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      if (tag === 'a') return mockAnchor
      return originalCreateElement(tag)
    })
    vi.spyOn(document.body, 'appendChild').mockImplementation(() => mockAnchor as any)
    vi.spyOn(document.body, 'removeChild').mockImplementation(() => mockAnchor as any)

    const wrapper = mountView()
    const downloadBtn = wrapper.findAll('button').find(b => b.text() === 'Download')
    await downloadBtn!.trigger('click')
    await flushPromises()

    expect(mockDownloadBlob).toHaveBeenCalledWith('blob-dl')
    expect(mockClick).toHaveBeenCalled()
    expect(mockAnchor.download).toBe('report.pdf')
    expect(URL.revokeObjectURL).toHaveBeenCalledWith(mockUrl)

    // Restore
    URL.createObjectURL = originalCreateObjectURL
    URL.revokeObjectURL = originalRevokeObjectURL
    vi.restoreAllMocks()
  })

  it('does nothing when downloadBlob returns null', async () => {
    mockBlobs.value = [
      { id: 'blob-fail', label: 'fail.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockDownloadBlob.mockResolvedValue(null)

    const createSpy = vi.spyOn(document, 'createElement')
    const wrapper = mountView()
    const downloadBtn = wrapper.findAll('button').find(b => b.text() === 'Download')
    await downloadBtn!.trigger('click')
    await flushPromises()

    // Should not create an anchor element
    expect(createSpy).not.toHaveBeenCalledWith('a')
    createSpy.mockRestore()
  })

  it('closes delete modal on overlay click', async () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()

    // Open delete modal
    const deleteBtns = wrapper.findAll('button').filter(b => b.text() === 'Delete')
    await deleteBtns[0].trigger('click')
    expect(wrapper.text()).toContain('Delete File')

    // Click overlay to close
    const overlay = wrapper.find('.vault42-modal-overlay')
    await overlay.trigger('click')

    // Modal should be gone (deleteConfirmId reset)
    expect(wrapper.find('.vault42-modal-overlay').exists()).toBe(false)
  })

  it('shows a spinner instead of the file list while the session is still resolving', () => {
    mockGuardLoading.value = true
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner-lg').exists()).toBe(true)
    expect(wrapper.find('h1').exists()).toBe(false)
    expect(wrapper.find('form').exists()).toBe(false)
  })

  it('renders a 0% quota bar instead of NaN when the account has no byte allowance', () => {
    mockQuota.value = { used_bytes: 0, max_bytes: 0, used_count: 0, max_count: 0 }
    const wrapper = mountView()

    const progressBar = wrapper.findAll('div').find(d => d.classes().includes('h-2') && d.attributes('style') !== undefined)
    expect(progressBar!.attributes('style')).toContain('0%')
    expect(progressBar!.attributes('style')).not.toContain('NaN')
    expect(progressBar!.classes()).toContain('bg-vault42-accent')
  })

  it('names the download after the blob label when the server response carries none', async () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'invoice.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockDownloadBlob.mockResolvedValue({ data: new ArrayBuffer(8) })

    const dl = captureDownload()
    const wrapper = mountView()
    await wrapper.findAll('button').find(b => b.text() === 'Download')!.trigger('click')
    await flushPromises()

    expect(dl.anchor.download).toBe('invoice.pdf')
    dl.restore()
  })

  it('names the download after the blob id when nothing carries a label', async () => {
    mockBlobs.value = [
      { id: 'blob-unlabelled', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockDownloadBlob.mockResolvedValue({ data: new ArrayBuffer(8) })

    const dl = captureDownload()
    const wrapper = mountView()
    await wrapper.findAll('button').find(b => b.text() === 'Download')!.trigger('click')
    await flushPromises()

    expect(dl.anchor.download).toBe('blob-unlabelled')
    dl.restore()
  })

  it('strips path separators and control characters from the download filename', async () => {
    mockBlobs.value = [
      { id: 'blob-evil', label: 'x', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockDownloadBlob.mockResolvedValue({ data: new ArrayBuffer(8), label: '../../etc/pa ss:wd?.txt' })

    const dl = captureDownload()
    const wrapper = mountView()
    await wrapper.findAll('button').find(b => b.text() === 'Download')!.trigger('click')
    await flushPromises()

    expect(dl.anchor.download).toBe('.._.._etc_pa_ss_wd_.txt')
    dl.restore()
  })

  it('truncates an over-long download filename to 255 characters', async () => {
    mockBlobs.value = [
      { id: 'blob-long', label: 'x', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    mockDownloadBlob.mockResolvedValue({ data: new ArrayBuffer(8), label: 'a'.repeat(300) + '.txt' })

    const dl = captureDownload()
    const wrapper = mountView()
    await wrapper.findAll('button').find(b => b.text() === 'Download')!.trigger('click')
    await flushPromises()

    expect(dl.anchor.download).toBe('a'.repeat(255))
    dl.restore()
  })

  it('closes delete modal on Cancel click', async () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()

    // Open delete modal
    const deleteBtns = wrapper.findAll('button').filter(b => b.text() === 'Delete')
    await deleteBtns[0].trigger('click')
    expect(wrapper.text()).toContain('Delete File')

    // Click Cancel
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')

    expect(wrapper.find('.vault42-modal-overlay').exists()).toBe(false)
  })

  it('closes the delete modal on Escape without deleting', async () => {
    mockBlobs.value = [
      { id: 'blob-1', label: 'doc.pdf', size_bytes: 1024, stored_bytes: 800, checksum: 'sha256:abc', created_at: '2026-02-24T10:00:00Z' },
    ]
    const wrapper = mountView()

    await wrapper.findAll('button').filter(b => b.text() === 'Delete')[0].trigger('click')
    await flushPromises()
    expect(wrapper.find('.vault42-modal-overlay').exists()).toBe(true)

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
    await flushPromises()

    expect(wrapper.find('.vault42-modal-overlay').exists()).toBe(false)
    expect(mockDeleteBlob).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
