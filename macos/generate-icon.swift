import AppKit
import Foundation

func drawIcon(in ctx: CGContext, size: CGFloat, fullBleed: Bool = false, edgeToEdgeSquircle: Bool = false) {
    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)

    let scale = size / 1024.0
    let margin: CGFloat = (fullBleed || edgeToEdgeSquircle) ? 0.0 : (100.0 * scale)
    let bodySize: CGFloat = size - 2 * margin
    let iconRect = CGRect(x: margin, y: margin, width: bodySize, height: bodySize)
    let cornerRadius: CGFloat = fullBleed ? 0.0 : (edgeToEdgeSquircle ? (230.0 * scale) : (185.0 * scale))
    let squirclePath = CGPath(roundedRect: iconRect, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)

    // 1. Native macOS Drop Shadow under Squircle (only when padded on macOS canvas)
    if !fullBleed && !edgeToEdgeSquircle {
        ctx.saveGState()
        ctx.setShadow(
            offset: CGSize(width: 0, height: -22.0 * scale),
            blur: 32.0 * scale,
            color: NSColor.black.withAlphaComponent(0.42).cgColor
        )
        ctx.addPath(squirclePath)
        ctx.setFillColor(NSColor(red: 0.015, green: 0.03, blue: 0.07, alpha: 1.0).cgColor)
        ctx.fillPath()
        ctx.restoreGState()
    }

    // 2. Base Surface (Clipped)
    ctx.saveGState()
    ctx.addPath(squirclePath)
    ctx.clip()

    let cs = CGColorSpaceCreateDeviceRGB()

    // Oceanic Deep Midnight / Sapphire Gradient
    let bgColors = [
        NSColor(red: 0.06, green: 0.13, blue: 0.29, alpha: 1.0).cgColor,
        NSColor(red: 0.027, green: 0.075, blue: 0.20, alpha: 1.0).cgColor,
        NSColor(red: 0.008, green: 0.024, blue: 0.08, alpha: 1.0).cgColor
    ] as CFArray
    if let bgGradient = CGGradient(colorsSpace: cs, colors: bgColors, locations: [0.0, 0.52, 1.0]) {
        ctx.drawLinearGradient(
            bgGradient,
            start: CGPoint(x: size / 2, y: size - margin),
            end: CGPoint(x: size / 2, y: margin),
            options: []
        )
    }

    let cx = size / 2.0
    let cy = size / 2.0
    let u = bodySize / 100.0
    func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: cx + x * u, y: cy - y * u) }

    // 3. Ambient cyan/indigo glow
    if size >= 32 {
        let outerGlowColors = [
            NSColor(red: 0.08, green: 0.68, blue: 1.00, alpha: 0.30).cgColor,
            NSColor(red: 0.24, green: 0.42, blue: 0.96, alpha: 0.13).cgColor,
            NSColor.clear.cgColor
        ] as CFArray
        if let outerGlow = CGGradient(colorsSpace: cs, colors: outerGlowColors, locations: [0.0, 0.48, 1.0]) {
            ctx.drawRadialGradient(
                outerGlow,
                startCenter: CGPoint(x: cx, y: cy),
                startRadius: 0,
                endCenter: CGPoint(x: cx, y: cy),
                endRadius: 44.0 * u,
                options: []
            )
        }
    }

    // 4. Tapered luminous horizon beam through the center node
    if size >= 48 {
        ctx.saveGState()
        let beam = CGMutablePath()
        beam.move(to: pt(-28, 0))
        beam.addQuadCurve(to: pt(0, -1.2), control: pt(-13, -1.2))
        beam.addQuadCurve(to: pt(28, 0), control: pt(13, -1.2))
        beam.addQuadCurve(to: pt(0, 1.2), control: pt(13, 1.2))
        beam.addQuadCurve(to: pt(-28, 0), control: pt(-13, 1.2))
        beam.closeSubpath()
        ctx.addPath(beam)
        ctx.clip()
        let beamColors = [
            NSColor(red: 0.22, green: 0.80, blue: 1.0, alpha: 0.0).cgColor,
            NSColor(red: 0.45, green: 0.90, blue: 1.0, alpha: 0.48).cgColor,
            NSColor(red: 0.85, green: 0.98, blue: 1.0, alpha: 0.72).cgColor,
            NSColor(red: 0.45, green: 0.90, blue: 1.0, alpha: 0.48).cgColor,
            NSColor(red: 0.22, green: 0.80, blue: 1.0, alpha: 0.0).cgColor
        ] as CFArray
        if let bg = CGGradient(colorsSpace: cs, colors: beamColors, locations: [0.0, 0.28, 0.5, 0.72, 1.0]) {
            ctx.drawLinearGradient(bg, start: pt(-28, 0), end: pt(28, 0), options: [])
        }
        ctx.restoreGState()
    }

    // 5. Mirrored Aerodynamic Glide Chevrons / Transfer Wings
    func glideWing(mirrored: Bool) -> CGPath {
        let s: CGFloat = mirrored ? -1.0 : 1.0
        let p = CGMutablePath()
        p.move(to: pt(-31 * s, -10.5 * s))
        p.addQuadCurve(to: pt(29 * s, -24.0 * s), control: pt(-1 * s, -27.0 * s))
        p.addQuadCurve(to: pt(13.5 * s, 0.5 * s), control: pt(23.5 * s, -11.0 * s))
        p.addQuadCurve(to: pt(1.5 * s, -11.5 * s), control: pt(7.5 * s, -6.5 * s))
        p.addQuadCurve(to: pt(-31 * s, -10.5 * s), control: pt(-15 * s, -12.5 * s))
        p.closeSubpath()
        return p
    }

    let upperWing = glideWing(mirrored: false)
    let lowerWing = glideWing(mirrored: true)

    // Upper wing (Sky Cyan -> Ice White)
    if size >= 64 {
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 18.0 * scale, color: NSColor(red: 0.22, green: 0.80, blue: 1.0, alpha: 0.52).cgColor)
        ctx.addPath(upperWing)
        ctx.setFillColor(NSColor(red: 0.22, green: 0.80, blue: 1.0, alpha: 0.28).cgColor)
        ctx.fillPath()
        ctx.restoreGState()
    }

    ctx.saveGState()
    ctx.addPath(upperWing)
    ctx.clip()
    let upperColors = [
        NSColor(red: 0.96, green: 0.99, blue: 1.00, alpha: 1.0).cgColor,
        NSColor(red: 0.42, green: 0.87, blue: 1.00, alpha: 1.0).cgColor,
        NSColor(red: 0.06, green: 0.63, blue: 0.97, alpha: 1.0).cgColor
    ] as CFArray
    if let ug = CGGradient(colorsSpace: cs, colors: upperColors, locations: [0.0, 0.52, 1.0]) {
        ctx.drawLinearGradient(ug, start: pt(29, -24), end: pt(-31, -10.5), options: [])
    }
    ctx.restoreGState()

    // Lower wing (Luminous Cyan -> Electric Indigo)
    if size >= 64 {
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: 18.0 * scale, color: NSColor(red: 0.35, green: 0.45, blue: 1.0, alpha: 0.52).cgColor)
        ctx.addPath(lowerWing)
        ctx.setFillColor(NSColor(red: 0.35, green: 0.45, blue: 1.0, alpha: 0.28).cgColor)
        ctx.fillPath()
        ctx.restoreGState()
    }

    ctx.saveGState()
    ctx.addPath(lowerWing)
    ctx.clip()
    let lowerColors = [
        NSColor(red: 0.56, green: 0.92, blue: 1.00, alpha: 1.0).cgColor,
        NSColor(red: 0.16, green: 0.66, blue: 0.98, alpha: 1.0).cgColor,
        NSColor(red: 0.38, green: 0.43, blue: 0.97, alpha: 1.0).cgColor
    ] as CFArray
    if let lg = CGGradient(colorsSpace: cs, colors: lowerColors, locations: [0.0, 0.52, 1.0]) {
        ctx.drawLinearGradient(lg, start: pt(-29, 24), end: pt(31, 10.5), options: [])
    }
    ctx.restoreGState()

    // Subtle specular rim on the wings at Retina sizes
    if size >= 128 {
        ctx.saveGState()
        ctx.setLineWidth(max(1.0, 2.0 * scale))
        ctx.addPath(upperWing)
        ctx.setStrokeColor(NSColor(white: 1.0, alpha: 0.42).cgColor)
        ctx.strokePath()
        ctx.addPath(lowerWing)
        ctx.setStrokeColor(NSColor(red: 0.72, green: 0.94, blue: 1.0, alpha: 0.34).cgColor)
        ctx.strokePath()
        ctx.restoreGState()
    }

    // 6. Central Glowing Cyan-White Horizon Node
    let nodeRadius: CGFloat = size <= 16 ? 1.4 : 4.8 * u
    if size >= 32 {
        let haloColors = [
            NSColor(red: 0.60, green: 0.96, blue: 1.0, alpha: 0.85).cgColor,
            NSColor(red: 0.18, green: 0.76, blue: 1.0, alpha: 0.20).cgColor,
            NSColor.clear.cgColor
        ] as CFArray
        if let hg = CGGradient(colorsSpace: cs, colors: haloColors, locations: [0.0, 0.55, 1.0]) {
            ctx.drawRadialGradient(
                hg,
                startCenter: CGPoint(x: cx, y: cy),
                startRadius: 0,
                endCenter: CGPoint(x: cx, y: cy),
                endRadius: nodeRadius * 2.5,
                options: []
            )
        }
    }

    ctx.saveGState()
    if size >= 64 {
        ctx.setShadow(offset: .zero, blur: 18.0 * scale, color: NSColor(red: 0.45, green: 0.92, blue: 1.0, alpha: 1.0).cgColor)
    }
    ctx.setFillColor(NSColor.white.cgColor)
    ctx.fillEllipse(in: CGRect(x: cx - nodeRadius, y: cy - nodeRadius, width: nodeRadius * 2, height: nodeRadius * 2))
    ctx.restoreGState()

    // 7. Glass Edge Rim along Squircle border
    if !fullBleed {
        ctx.addPath(squirclePath)
        ctx.setLineWidth(max(1.0, 2.0 * scale))
        let rimColors = [
            NSColor(white: 1.0, alpha: 0.32).cgColor,
            NSColor(white: 1.0, alpha: 0.06).cgColor
        ] as CFArray
        if let rimGrad = CGGradient(colorsSpace: cs, colors: rimColors, locations: [0.0, 1.0]) {
            ctx.replacePathWithStrokedPath()
            ctx.clip()
            ctx.drawLinearGradient(
                rimGrad,
                start: CGPoint(x: size / 2, y: size - margin),
                end: CGPoint(x: size / 2, y: margin),
                options: []
            )
        }
    }

    ctx.restoreGState()
}

func renderExactPng(pixels: Int, fullBleed: Bool = false, edgeToEdgeSquircle: Bool = false) -> Data {
    let size = CGFloat(pixels)
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    let bitmapInfo = CGImageAlphaInfo.premultipliedLast.rawValue
    guard let ctx = CGContext(
        data: nil,
        width: pixels,
        height: pixels,
        bitsPerComponent: 8,
        bytesPerRow: pixels * 4,
        space: colorSpace,
        bitmapInfo: bitmapInfo
    ) else {
        fatalError("Failed to create CGContext for \(pixels)x\(pixels)")
    }

    drawIcon(in: ctx, size: size, fullBleed: fullBleed, edgeToEdgeSquircle: edgeToEdgeSquircle)

    guard let cgImage = ctx.makeImage() else {
        fatalError("Failed to create CGImage")
    }

    let rep = NSBitmapImageRep(cgImage: cgImage)
    guard let pngData = rep.representation(using: .png, properties: [:]) else {
        fatalError("Failed to export PNG data")
    }

    return pngData
}

private enum IconGenError: Error, LocalizedError {
    case iconutilFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .iconutilFailed(let code):
            return "iconutil failed with exit code \(code)"
        }
    }
}

private func runGenerateIcon() throws {
    let fileManager = FileManager.default
    let scriptURL = URL(fileURLWithPath: CommandLine.arguments[0])
    let scriptDir = scriptURL.deletingLastPathComponent().path
    let defaultIcnsPath: String
    if fileManager.fileExists(atPath: (scriptDir as NSString).appendingPathComponent("generate-icon.swift")) {
        defaultIcnsPath = (scriptDir as NSString).appendingPathComponent("AppIcon.icns")
    } else if fileManager.fileExists(atPath: "macos/generate-icon.swift") {
        defaultIcnsPath = "macos/AppIcon.icns"
    } else {
        defaultIcnsPath = (scriptDir as NSString).appendingPathComponent("AppIcon.icns")
    }

    // Optional mode: --web <icon512Path> <appleTouch180Path>
    if CommandLine.arguments.count >= 4 && CommandLine.arguments[1] == "--web" {
        let icon512 = renderExactPng(pixels: 512, fullBleed: false, edgeToEdgeSquircle: true)
        let touch180 = renderExactPng(pixels: 180, fullBleed: true, edgeToEdgeSquircle: false)
        try icon512.write(to: URL(fileURLWithPath: CommandLine.arguments[2]))
        try touch180.write(to: URL(fileURLWithPath: CommandLine.arguments[3]))
        print("[+] Generated web icon PNGs")
        return
    }

    let targetIcnsPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : defaultIcnsPath

    let tempWorkDir = fileManager.temporaryDirectory
        .appendingPathComponent("glidedrop-icon-\(UUID().uuidString)", isDirectory: true)
    try fileManager.createDirectory(
        at: tempWorkDir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    defer {
        try? fileManager.removeItem(at: tempWorkDir)
    }

    let iconsetDir = tempWorkDir.appendingPathComponent("AppIcon.iconset", isDirectory: true)
    try fileManager.createDirectory(
        at: iconsetDir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )

    let iconSizes: [(String, Int)] = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024)
    ]

    for (name, pixels) in iconSizes {
        let pngData = renderExactPng(pixels: pixels)
        let destURL = iconsetDir.appendingPathComponent(name)
        try pngData.write(to: destURL)
    }

    print("[+] Successfully generated all 10 canonical resolutions in \(iconsetDir.path)")

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    process.arguments = ["-c", "icns", iconsetDir.path, "-o", targetIcnsPath]

    try process.run()
    process.waitUntilExit()

    if process.terminationStatus == 0 {
        print("[+] Successfully compiled ICNS to: \(targetIcnsPath)")
    } else {
        throw IconGenError.iconutilFailed(process.terminationStatus)
    }
}

private let _generateIconEntryPoint: Void = {
    do {
        try runGenerateIcon()
    } catch {
        fputs("[-] \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}()
