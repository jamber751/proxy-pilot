import SwiftUI

enum PilotTheme {
    static let accent = Color(red: 0.12, green: 0.53, blue: 0.39)
}

/// The hit region is defined inside each label; feedback never intercepts clicks.
struct PilotButtonStyle: ButtonStyle {
    var cornerRadius: CGFloat = 8
    var highlightsSurface = true

    func makeBody(configuration: Configuration) -> some View {
        Feedback(label: configuration.label, pressed: configuration.isPressed,
                 cornerRadius: cornerRadius, highlightsSurface: highlightsSurface)
    }

    private struct Feedback<Label: View>: View {
        let label: Label
        let pressed: Bool
        let cornerRadius: CGFloat
        let highlightsSurface: Bool
        @Environment(\.isEnabled) private var enabled
        @State private var hovering = false

        var body: some View {
            label
                .overlay(RoundedRectangle(cornerRadius: cornerRadius)
                    .fill(Color.primary.opacity(enabled && highlightsSurface ? (pressed ? 0.12 : hovering ? 0.06 : 0) : 0))
                    .allowsHitTesting(false))
                .brightness(enabled && hovering && !highlightsSurface ? 0.07 : 0)
                .opacity(enabled ? (pressed ? 0.8 : 1) : 0.4)
                .scaleEffect(enabled && pressed ? 0.985 : 1)
                .onHover { value in
                    withAnimation(.easeOut(duration: 0.12)) { hovering = value }
                }
        }
    }
}

struct PilotCheckboxStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(configuration.isOn ? PilotTheme.accent : Color.primary.opacity(0.06))
                    RoundedRectangle(cornerRadius: 4)
                        .stroke(Color.primary.opacity(configuration.isOn ? 0 : 0.25), lineWidth: 1)
                    if configuration.isOn {
                        Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundColor(.white)
                    }
                }.frame(width: 16, height: 16)
                configuration.label
                Spacer(minLength: 0)
            }.frame(maxWidth: .infinity, minHeight: 28, alignment: .leading)
                .contentShape(Rectangle())
        }.buttonStyle(PilotButtonStyle())
            .accessibilityValue(configuration.isOn ? "Включено" : "Выключено")
    }
}
