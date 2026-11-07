import AppKit

func createIcon(size: CGFloat) -> NSImage {
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()
    guard let ctx = NSGraphicsContext.current?.cgContext else {
        img.unlockFocus()
        return img
    }

    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)

    let scale = size / 1024.0

    // 1. macOS Squircle Shape (App Icon Grid)
    let margin: CGFloat = 80.0 * scale
    let iconRect = CGRect(x: margin, y: margin, width: size - 2 * margin, height: size - 2 * margin)
    let cornerRadius: CGFloat = 195.0 * scale
    let path = CGPath(roundedRect: iconRect, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)

    // Shadow
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12.0 * scale), blur: 30.0 * scale, color: NSColor.black.withAlphaComponent(0.45).cgColor)
    ctx.addPath(path)
    ctx.setFillColor(NSColor(red: 0.05, green: 0.07, blue: 0.12, alpha: 1.0).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // Base Squircle Background Gradient
    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()

    let colorSpace = CGColorSpaceCreateDeviceRGB()
    let bgColors = [
        NSColor(red: 0.07, green: 0.11, blue: 0.20, alpha: 1.0).cgColor,
        NSColor(red: 0.04, green: 0.06, blue: 0.12, alpha: 1.0).cgColor,
        NSColor(red: 0.02, green: 0.03, blue: 0.06, alpha: 1.0).cgColor
    ] as CFArray
    let bgLocations: [CGFloat] = [0.0, 0.55, 1.0]
    if let bgGradient = CGGradient(colorsSpace: colorSpace, colors: bgColors, locations: bgLocations) {
        ctx.drawLinearGradient(bgGradient, start: CGPoint(x: size/2, y: size - margin), end: CGPoint(x: size/2, y: margin), options: [])
    }

    // Radial Ambient Glow from center
    let glowColors = [
        NSColor(red: 0.06, green: 0.65, blue: 0.95, alpha: 0.28).cgColor,
        NSColor(red: 0.02, green: 0.35, blue: 0.75, alpha: 0.08).cgColor,
        NSColor(red: 0.0, green: 0.0, blue: 0.0, alpha: 0.0).cgColor
    ] as CFArray
    if let glowGradient = CGGradient(colorsSpace: colorSpace, colors: glowColors, locations: [0.0, 0.5, 1.0]) {
        ctx.drawRadialGradient(glowGradient, startCenter: CGPoint(x: size/2, y: size * 0.48), startRadius: 0, endCenter: CGPoint(x: size/2, y: size * 0.48), endRadius: 360.0 * scale, options: [])
    }

    // 2. AirDrop Radar Broadcast Rings
    let centerX = size / 2.0
    let centerY = size * 0.46

    func drawRing(radius: CGFloat, strokeWidth: CGFloat, strokeColor: NSColor, startDeg: CGFloat = 35.0, endDeg: CGFloat = 145.0) {
        ctx.saveGState()
        ctx.setLineCap(.round)
        ctx.setLineWidth(strokeWidth * scale)
        ctx.setStrokeColor(strokeColor.cgColor)
        
        let startAngle = (180.0 + startDeg) * .pi / 180.0
        let endAngle = (360.0 - startDeg) * .pi / 180.0
        ctx.addArc(center: CGPoint(x: centerX, y: centerY), radius: radius * scale, startAngle: startAngle, endAngle: endAngle, clockwise: false)
        ctx.strokePath()
        ctx.restoreGState()
    }

    // Outer Arc
    drawRing(radius: 275.0, strokeWidth: 32.0, strokeColor: NSColor(red: 0.22, green: 0.74, blue: 0.97, alpha: 0.95), startDeg: 36.0)
    // Middle Arc
    drawRing(radius: 195.0, strokeWidth: 34.0, strokeColor: NSColor(red: 0.05, green: 0.65, blue: 0.95, alpha: 0.98), startDeg: 34.0)
    // Inner Arc
    drawRing(radius: 118.0, strokeWidth: 36.0, strokeColor: NSColor(red: 0.49, green: 0.83, blue: 0.99, alpha: 1.0), startDeg: 30.0)

    // Center Pulse Beacon (Transmitter cone & circle)
    let beaconPath = CGMutablePath()
    let tip = CGPoint(x: centerX, y: centerY + 45.0 * scale)
    let leftBase = CGPoint(x: centerX - 42.0 * scale, y: centerY - 130.0 * scale)
    let rightBase = CGPoint(x: centerX + 42.0 * scale, y: centerY - 130.0 * scale)

    beaconPath.move(to: tip)
    beaconPath.addLine(to: rightBase)
    beaconPath.addQuadCurve(to: leftBase, control: CGPoint(x: centerX, y: centerY - 142.0 * scale))
    beaconPath.closeSubpath()

    ctx.saveGState()
    ctx.addPath(beaconPath)
    let beaconColors = [
        NSColor(red: 0.45, green: 0.88, blue: 1.0, alpha: 1.0).cgColor,
        NSColor(red: 0.06, green: 0.65, blue: 0.95, alpha: 1.0).cgColor
    ] as CFArray
    if let bGrad = CGGradient(colorsSpace: colorSpace, colors: beaconColors, locations: [0.0, 1.0]) {
        ctx.drawLinearGradient(bGrad, start: tip, end: CGPoint(x: centerX, y: centerY - 135.0 * scale), options: [])
    }
    ctx.restoreGState()

    // Center Core Glow Dot
    let dotRect = CGRect(x: centerX - 20.0 * scale, y: centerY + 30.0 * scale, width: 40.0 * scale, height: 40.0 * scale)
    ctx.saveGState()
    ctx.setFillColor(NSColor.white.cgColor)
    ctx.setShadow(offset: .zero, blur: 18.0 * scale, color: NSColor(red: 0.38, green: 0.85, blue: 1.0, alpha: 1.0).cgColor)
    ctx.fillEllipse(in: dotRect)
    ctx.restoreGState()

    // Inner subtle border highlight around the squircle
    ctx.addPath(path)
    ctx.setLineWidth(2.5 * scale)
    ctx.setStrokeColor(NSColor(white: 1.0, alpha: 0.16).cgColor)
    ctx.strokePath()

    ctx.restoreGState() // restore squircle clip

    img.unlockFocus()
    return img
}

let iconsetDir = URL(fileURLWithPath: "/tmp/AppIcon.iconset")
try? FileManager.default.removeItem(at: iconsetDir)
try FileManager.default.createDirectory(at: iconsetDir, withIntermediateDirectories: true)

let sizes: [(String, CGFloat)] = [
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

for (name, sz) in sizes {
    let img = createIcon(size: sz)
    if let tiff = img.tiffRepresentation,
       let rep = NSBitmapImageRep(data: tiff),
       let png = rep.representation(using: .png, properties: [:]) {
        let fileURL = iconsetDir.appendingPathComponent(name)
        try png.write(to: fileURL)
    }
}

print("[+] Generated AppIcon.iconset successfully")
