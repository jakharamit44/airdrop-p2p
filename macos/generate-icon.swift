import AppKit

func drawIcon(in ctx: CGContext, size: CGFloat) {
    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)

    let scale = size / 1024.0

    // Apple macOS Icon Grid (1024 x 1024 canvas)
    // Body: 824 x 824 centered (100 pt margins)
    let margin: CGFloat = 100.0 * scale
    let bodySize: CGFloat = size - 2 * margin
    let iconRect = CGRect(x: margin, y: margin, width: bodySize, height: bodySize)
    let cornerRadius: CGFloat = 185.0 * scale
    let squirclePath = CGPath(roundedRect: iconRect, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)

    // 1. Drop Shadow under Squircle
    ctx.saveGState()
    ctx.setShadow(
        offset: CGSize(width: 0, height: -18.0 * scale),
        blur: 28.0 * scale,
        color: NSColor.black.withAlphaComponent(0.35).cgColor
    )
    ctx.addPath(squirclePath)
    ctx.setFillColor(NSColor(red: 0.03, green: 0.05, blue: 0.10, alpha: 1.0).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // 2. Base Squircle Surface (Clipped)
    ctx.saveGState()
    ctx.addPath(squirclePath)
    ctx.clip()

    let colorSpace = CGColorSpaceCreateDeviceRGB()

    // Oceanic Deep Navy / Midnight Gradient (Sonoma/Sequoia aesthetic)
    let bgColors = [
        NSColor(red: 0.08, green: 0.14, blue: 0.28, alpha: 1.0).cgColor, // Top
        NSColor(red: 0.04, green: 0.07, blue: 0.16, alpha: 1.0).cgColor, // Mid
        NSColor(red: 0.02, green: 0.03, blue: 0.08, alpha: 1.0).cgColor  // Bottom
    ] as CFArray
    let bgLocations: [CGFloat] = [0.0, 0.55, 1.0]
    if let bgGradient = CGGradient(colorsSpace: colorSpace, colors: bgColors, locations: bgLocations) {
        ctx.drawLinearGradient(
            bgGradient,
            start: CGPoint(x: size / 2, y: size - margin),
            end: CGPoint(x: size / 2, y: margin),
            options: []
        )
    }

    // Ambient Cyan/Blue Core Glow
    let glowCenter = CGPoint(x: size / 2.0, y: size * 0.46)
    let glowColors = [
        NSColor(red: 0.06, green: 0.65, blue: 0.98, alpha: 0.32).cgColor,
        NSColor(red: 0.02, green: 0.38, blue: 0.85, alpha: 0.12).cgColor,
        NSColor(red: 0.0, green: 0.0, blue: 0.0, alpha: 0.0).cgColor
    ] as CFArray
    if let glowGradient = CGGradient(colorsSpace: colorSpace, colors: glowColors, locations: [0.0, 0.45, 1.0]) {
        ctx.drawRadialGradient(
            glowGradient,
            startCenter: glowCenter,
            startRadius: 0,
            endCenter: glowCenter,
            endRadius: 380.0 * scale,
            options: []
        )
    }

    // 3. AirDrop Concentric Radiating Rings
    let centerX = size / 2.0
    let centerY = size * 0.44

    func drawRing(radius: CGFloat, strokeWidth: CGFloat, strokeColor: NSColor, startDeg: CGFloat = 32.0, endDeg: CGFloat = 148.0) {
        ctx.saveGState()
        ctx.setLineCap(.round)
        let effectiveWidth = max(size <= 32 ? 2.5 : 1.5, strokeWidth * scale)
        ctx.setLineWidth(effectiveWidth)
        ctx.setStrokeColor(strokeColor.cgColor)

        // In standard AppKit coords (y=0 bottom, y=size top), angles 0=right, 90=top, 180=left.
        // Broadcast upward: startDeg ~32 to endDeg ~148
        let startAngle = startDeg * .pi / 180.0
        let endAngle = endDeg * .pi / 180.0
        ctx.addArc(
            center: CGPoint(x: centerX, y: centerY),
            radius: radius * scale,
            startAngle: startAngle,
            endAngle: endAngle,
            clockwise: false
        )
        ctx.strokePath()
        ctx.restoreGState()
    }

    // Outer Arc
    drawRing(
        radius: 260.0,
        strokeWidth: 30.0,
        strokeColor: NSColor(red: 0.22, green: 0.74, blue: 0.97, alpha: 0.95),
        startDeg: 34.0,
        endDeg: 146.0
    )
    // Middle Arc
    drawRing(
        radius: 182.0,
        strokeWidth: 32.0,
        strokeColor: NSColor(red: 0.05, green: 0.65, blue: 0.95, alpha: 0.98),
        startDeg: 30.0,
        endDeg: 150.0
    )
    // Inner Arc
    drawRing(
        radius: 108.0,
        strokeWidth: 34.0,
        strokeColor: NSColor(red: 0.49, green: 0.83, blue: 0.99, alpha: 1.0),
        startDeg: 24.0,
        endDeg: 156.0
    )

    // Center Transmitter Pulse Beacon (Arrow/Cone pointing UP towards radiating arcs)
    let beaconPath = CGMutablePath()
    let tip = CGPoint(x: centerX, y: centerY + 50.0 * scale)
    let leftBase = CGPoint(x: centerX - 36.0 * scale, y: centerY - 95.0 * scale)
    let rightBase = CGPoint(x: centerX + 36.0 * scale, y: centerY - 95.0 * scale)

    beaconPath.move(to: tip)
    beaconPath.addLine(to: rightBase)
    beaconPath.addQuadCurve(to: leftBase, control: CGPoint(x: centerX, y: centerY - 105.0 * scale))
    beaconPath.closeSubpath()

    ctx.saveGState()
    ctx.addPath(beaconPath)
    let beaconColors = [
        NSColor(red: 0.55, green: 0.90, blue: 1.0, alpha: 1.0).cgColor,
        NSColor(red: 0.08, green: 0.65, blue: 0.95, alpha: 1.0).cgColor
    ] as CFArray
    if let bGrad = CGGradient(colorsSpace: colorSpace, colors: beaconColors, locations: [0.0, 1.0]) {
        ctx.drawLinearGradient(bGrad, start: tip, end: CGPoint(x: centerX, y: centerY - 100.0 * scale), options: [])
    }
    ctx.restoreGState()

    // Center Core Pulse Dot (White core with electric cyan halo)
    let dotRadius: CGFloat = max(size <= 32 ? 2.5 : 2.0, 18.0 * scale)
    let dotRect = CGRect(x: centerX - dotRadius, y: centerY + 36.0 * scale - dotRadius, width: dotRadius * 2, height: dotRadius * 2)
    ctx.saveGState()
    ctx.setFillColor(NSColor.white.cgColor)
    ctx.setShadow(
        offset: .zero,
        blur: max(2.0, 16.0 * scale),
        color: NSColor(red: 0.40, green: 0.86, blue: 1.0, alpha: 1.0).cgColor
    )
    ctx.fillEllipse(in: dotRect)
    ctx.restoreGState()

    // 4. Subtle Specular Highlight Rim along the squircle border
    ctx.addPath(squirclePath)
    ctx.setLineWidth(max(1.0, 2.0 * scale))
    let rimColors = [
        NSColor(white: 1.0, alpha: 0.28).cgColor,
        NSColor(white: 1.0, alpha: 0.06).cgColor
    ] as CFArray
    if let rimGrad = CGGradient(colorsSpace: colorSpace, colors: rimColors, locations: [0.0, 1.0]) {
        ctx.saveGState()
        ctx.replacePathWithStrokedPath()
        ctx.clip()
        ctx.drawLinearGradient(rimGrad, start: CGPoint(x: size / 2, y: size - margin), end: CGPoint(x: size / 2, y: margin), options: [])
        ctx.restoreGState()
    }

    ctx.restoreGState() // End Squircle Clip
}

func renderExactPng(pixels: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixels,
        pixelsHigh: pixels,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!
    rep.size = NSSize(width: pixels, height: pixels)

    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = ctx
    let cg = ctx.cgContext
    cg.clear(CGRect(x: 0, y: 0, width: pixels, height: pixels))
    drawIcon(in: cg, size: CGFloat(pixels))
    NSGraphicsContext.restoreGraphicsState()

    guard let pngData = rep.representation(using: .png, properties: [:]) else {
        fatalError("Failed to encode PNG for size \(pixels)")
    }
    return pngData
}

let iconsetDir = URL(fileURLWithPath: "/tmp/AppIcon.iconset")
try? FileManager.default.removeItem(at: iconsetDir)
try FileManager.default.createDirectory(at: iconsetDir, withIntermediateDirectories: true)

// Apple iconset canonical resolution specifications
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
    let png = renderExactPng(pixels: pixels)
    let destURL = iconsetDir.appendingPathComponent(name)
    try png.write(to: destURL)
}

print("[+] Successfully generated all 10 canonical resolutions in /tmp/AppIcon.iconset")
