import AppKit
import Combine
import SwiftUI

/// AppKit replacement for `MenuBarExtra(.window)`: MenuBarExtra labels ignore
/// context menus on macOS, so right-click actions (lock/unlock, quit) need a
/// real NSStatusItem. Left click toggles the floating panel hosting
/// SecretBarView; right click pops a native menu built from current state.
@MainActor
final class SecretBarStatusItemController: NSObject, NSWindowDelegate {
    private var statusItem: NSStatusItem?
    private var panel: KeyablePanel?
    private var stateCancellable: AnyCancellable?
    private var rightClickMonitor: Any?
    private weak var model: SecretBarModel?

    private let panelSize = NSSize(width: 620, height: 700)

    func start(model: SecretBarModel) {
        self.model = model

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem = item

        if let button = item.button {
            button.image = Self.iconImage(for: model.state)
            button.target = self
            button.action = #selector(statusItemClick)
        }

        // Keep the lock/locked/error glyph in sync with vault state.
        stateCancellable = model.$state
            .receive(on: RunLoop.main)
            .sink { [weak self] state in
                self?.statusItem?.button?.image = Self.iconImage(for: state)
            }

        // Right click on the status item opens the context menu instead of
        // toggling the panel. Status item windows belong to this process, so
        // a local event monitor sees them.
        rightClickMonitor = NSEvent.addLocalMonitorForEvents(matching: .rightMouseDown) { [weak self] event in
            MainActor.assumeIsolated {
                guard let self, event.window === self.statusItem?.button?.window else { return event }
                self.showContextMenu()
                return nil as NSEvent?
            }
        }
    }

    // MARK: - Icon

    private static func iconImage(for state: VaultState) -> NSImage? {
        let symbol: String
        switch state {
        case .unlocked: symbol = "lock.open.fill"
        case .locked: symbol = "lock.fill"
        case .unauthenticated, .error: symbol = "exclamationmark.triangle.fill"
        case .unknown: symbol = "circle.dashed"
        }
        let configuration = NSImage.SymbolConfiguration(pointSize: 13, weight: .medium)
        return NSImage(systemSymbolName: symbol, accessibilityDescription: "SecretBar")?
            .withSymbolConfiguration(configuration)
    }

    // MARK: - Panel

    @objc private func statusItemClick() {
        togglePanel()
    }

    func togglePanel() {
        if let panel, panel.isVisible {
            hidePanel()
        } else {
            showPanel()
        }
    }

    func showPanel() {
        guard let model else { return }
        let targetPanel = ensurePanel(model: model)
        positionPanel(targetPanel)
        targetPanel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func hidePanel() {
        panel?.orderOut(nil)
    }

    private func ensurePanel(model: SecretBarModel) -> KeyablePanel {
        if let panel { return panel }
        let newPanel = KeyablePanel(
            contentRect: NSRect(origin: .zero, size: panelSize),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        newPanel.isOpaque = false
        newPanel.backgroundColor = .clear
        newPanel.hasShadow = true
        newPanel.isMovableByWindowBackground = false
        newPanel.level = .statusBar
        newPanel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        newPanel.hidesOnDeactivate = false
        newPanel.contentView = NSHostingView(rootView: SecretBarView().environmentObject(model))
        newPanel.delegate = self
        panel = newPanel
        return newPanel
    }

    private func positionPanel(_ targetPanel: NSPanel) {
        guard let buttonWindow = statusItem?.button?.window else { return }
        let buttonFrame = buttonWindow.frame
        let size = targetPanel.frame.size
        var origin = NSPoint(
            x: buttonFrame.midX - size.width / 2,
            y: buttonFrame.minY - size.height - 6
        )
        if let screen = buttonWindow.screen ?? NSScreen.main {
            let visible = screen.visibleFrame
            origin.x = min(max(origin.x, visible.minX + 8), max(visible.minX + 8, visible.maxX - size.width - 8))
            if origin.y < visible.minY + 8 {
                origin.y = visible.minY + 8
            }
        }
        targetPanel.setFrameOrigin(origin)
    }

    // Closing when the panel loses key focus gives the usual
    // click-outside-to-dismiss behavior for a menu bar popover.
    func windowDidResignKey(_ notification: Notification) {
        hidePanel()
    }

    // MARK: - Context menu

    private func showContextMenu() {
        guard let item = statusItem, let model else { return }
        hidePanel()
        item.menu = buildMenu(model: model)
        item.button?.performClick(nil) // pops the menu synchronously under the icon
        item.menu = nil
    }

    private func buildMenu(model: SecretBarModel) -> NSMenu {
        let menu = NSMenu()

        if model.showMainWindow {
            let open = NSMenuItem(title: "Open Main Window", action: #selector(openFromMenu(_:)), keyEquivalent: "")
            open.target = self
            menu.addItem(open)
        }

        switch model.state {
        case .unlocked:
            menu.addItem(.separator())
            let lock = NSMenuItem(title: "Lock vault", action: #selector(lockFromMenu(_:)), keyEquivalent: "")
            lock.target = self
            lock.isEnabled = !model.busy
            menu.addItem(lock)
        case .locked:
            menu.addItem(.separator())
            let touchID = NSMenuItem(title: "Unlock with Touch ID", action: #selector(touchIDFromMenu(_:)), keyEquivalent: "")
            touchID.target = self
            touchID.isEnabled = !model.busy && model.biometricCacheAvailable
            menu.addItem(touchID)
            let password = NSMenuItem(title: "Unlock with master password…", action: #selector(openFromMenu(_:)), keyEquivalent: "")
            password.target = self
            menu.addItem(password)
        case .unknown, .unauthenticated, .error:
            break
        }

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit SecretBar", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        return menu
    }

    @objc private func openFromMenu(_ sender: NSMenuItem) {
        showPanel()
    }

    @objc private func lockFromMenu(_ sender: NSMenuItem) {
        model?.lock()
    }

    @objc private func touchIDFromMenu(_ sender: NSMenuItem) {
        model?.unlockWithTouchID()
    }
}

/// Borderless panels cannot become key by default; the search field and
/// sheets inside SecretBarView need key focus.
final class KeyablePanel: NSPanel {
    override var canBecomeKey: Bool { true }
}
